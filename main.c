/*
 *
 * Copyright 2023 Kenichi Yasukata
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include <sched.h>

#include <sys/ioctl.h>
#include <sys/poll.h>
#include <net/if.h>
#include <linux/rtnetlink.h>
#include <linux/if_xdp.h>

#include <linux/if_ether.h>

#include <pthread.h>
#include <numa.h>

#ifdef XSK_HEADER_LIBBPF
#include <bpf/xsk.h>
#endif
#ifdef XSK_HEADER_LIBXDP
#include <xdp/xsk.h>
#endif

#define __IOSUB_MAX_CORE (256)

#ifndef NUM_RX_DESC
#define NUM_RX_DESC (XSK_RING_CONS__DEFAULT_NUM_DESCS)
#endif
#ifndef NUM_TX_DESC
#define NUM_TX_DESC (XSK_RING_PROD__DEFAULT_NUM_DESCS)
#endif
#define NUM_BUF (4096 > ((NUM_RX_DESC + NUM_TX_DESC) * 4) ? 4096 : ((NUM_RX_DESC + NUM_TX_DESC) * 4))
#define BUF_SIZE (XSK_UMEM__DEFAULT_FRAME_SIZE)
#ifndef NUM_NETSTACK_PB
#define NUM_NETSTACK_PB (8192)
#endif
#ifndef NUM_NETSTACK_TCP_CONN
#define NUM_NETSTACK_TCP_CONN (512)
#endif
#ifndef ETH_RX_BATCH
#define ETH_RX_BATCH (64)
#endif
#ifndef ETH_TX_BATCH
#define ETH_TX_BATCH ETH_RX_BATCH
#endif
#define ETH_TX_CHAIN_MAX (16)
#if (NUM_TX_DESC < ETH_TX_BATCH + ETH_TX_CHAIN_MAX) /* avoid exceeding limit in eth push / flush */
#error "too large max chain and batch"
#endif

#define __IOSUB_BUF_IDX(__addr) (((__addr) & ~(BUF_SIZE - 1)) / BUF_SIZE)
#define __IOSUB_BUF_ADDR_ASSERT(__iop, __addr) do { assert((__IOSUB_BUF_IDX(__addr)) < NUM_BUF); } while (0)
#define __IOSUB_BUF_REFCNT(__iop, __addr) ((__iop)->af_xdp.buf_ref[__IOSUB_BUF_IDX(__addr)])

#ifndef __IOSUB_BUSY_POLL_SOCK
#define __IOSUB_BUSY_POLL_SOCK (1)
#endif

struct __xpb {
	uint64_t addr;
	uint16_t len;
	uint16_t head;
	struct __xpb *next[2];
	struct __xpb *prev[2];
};

struct io_opaque {
	struct {
		struct xsk_socket *xsk;
		void *umem_area;
		struct xsk_ring_cons *complete_ring;
		struct xsk_ring_prod *tx_ring;
		uint16_t eth_sent;
		struct {
			uint32_t free_cnt;
			struct __xpb *free_p[NUM_NETSTACK_PB];
			struct __xpb p[NUM_NETSTACK_PB];
			struct __xpb_bufmem *buf[1][2];
		} pool;
		uint16_t buf_ref[NUM_BUF];
		uint32_t free_buf_cnt;
		uint64_t free_buf_addr[NUM_BUF];
	} af_xdp;
	struct {
		struct {
			struct __xpb *m[ETH_TX_BATCH];
			uint16_t cnt;
			uint16_t num_pkt;
		} tx;
	} eth;
	struct {
		struct {
			uint64_t rx_pkt;
			uint64_t rx_drop;
			uint64_t tx_pkt;
			uint64_t tx_fail;
		} eth;
	} stat[2];
};

static _Atomic uint8_t stat_idx = 0;

static uint8_t mac_addr[6] = { 0 };
static uint32_t ip4_addr_be = 0;
static struct io_opaque io_opaque[__IOSUB_MAX_CORE] = { 0 };

static const char *__iosub_ifname = NULL;
static uint16_t __iosub_num_cores = 0;
static uint16_t __iosub_core_list[__IOSUB_MAX_CORE];

static uint16_t __iosub_rss_tbl_cached[512] = { 0 };
static uint16_t __iosub_rss_tbl_size_cached = 0;
static uint8_t __iosub_rss_key_cached[256] = { 0 };
static uint16_t __iosub_rss_key_size_cached = 0;

static int32_t __iosub_max_poll_wait_ms = 1000U; /* 1 sec */

static uint16_t helper_ip4_get_connection_affinity(uint16_t protocol, uint32_t local_ip4_be, uint16_t local_port_be, uint32_t peer_ip4_be, uint16_t peer_port_be, void *opaque)
{
	if (!__iosub_rss_tbl_size_cached) {
		char tbl_buf[1024] = { 0 };
		{
			char cmdbuf[512];
			assert((size_t) snprintf(cmdbuf, sizeof(cmdbuf),
						"ethtool -x %s| awk '/RX/,/RSS/' | grep -v RX | grep -v RSS | awk '{ $1=\"\"; print }' | sed -z 's/\\n//g'",
						__iosub_ifname) < sizeof(cmdbuf));
			{
				FILE *fp;
				assert((fp = popen(cmdbuf, "r")) != NULL);
				{
					size_t i;
					for (i = 0; i < sizeof(tbl_buf) - 1; i++) {
						if ((tbl_buf[i] = fgetc(fp)) == EOF) {
							tbl_buf[i] = '\0';
							break;
						}
					}
					assert(i < sizeof(tbl_buf));
				}
				pclose(fp);
			}
		}
		{
			size_t i, j, k, l = strlen(tbl_buf);
			for (i = 0, j = 0, k = 0; i <= l && k < sizeof(__iosub_rss_tbl_cached) / sizeof(uint16_t); i++) {
				if (tbl_buf[i] == ' ' || i == l) {
					tbl_buf[i] = '\0';
					if (i != j)
						__iosub_rss_tbl_cached[k++] = atoi(&tbl_buf[j]);
					j = i + 1;
				}
			}
			asm volatile ("" ::: "memory");
			__iosub_rss_tbl_size_cached = k;
		}
	}
	if (!__iosub_rss_key_size_cached) {
		char key_buf[1024] = { 0 };
		{
			char cmdbuf[512];
			assert((size_t) snprintf(cmdbuf, sizeof(cmdbuf),
						"ethtool -x %s | awk '/RSS hash key/,/RSS hash function/' | grep -v RSS | sed -z 's/\\n//g' | sed -z 's/:/ /g' ",
						__iosub_ifname) < sizeof(cmdbuf));
			{
				FILE *fp;
				assert((fp = popen(cmdbuf, "r")) != NULL);
				{
					size_t i;
					for (i = 0; i < sizeof(key_buf) - 1; i++) {
						if ((key_buf[i] = fgetc(fp)) == EOF) {
							key_buf[i] = '\0';
							break;
						}
					}
					assert(i < sizeof(key_buf));
				}
				pclose(fp);
			}
		}
		{
			size_t i, j, k, l = strlen(key_buf);
			for (i = 0, j = 0, k = 0; i <= l && k < sizeof(__iosub_rss_key_cached); i++) {
				if (key_buf[i] == ' ' || i == l) {
					key_buf[i] = '\0';
					if (i != j)
						__iosub_rss_key_cached[k++] = strtol(&key_buf[j], NULL, 16);
					j = i + 1;
				}
			}
			asm volatile ("" ::: "memory");
			__iosub_rss_key_size_cached = k;
		}
	}
	{ /* toeplitz hash */
		/*
		 * XXX:
		 * mlx5 driver for Linux activates the symmetric hash mode
		 * when the toeplitz hash is selected (by default),
		 * and this symmetric hash mode gives a different result
		 * from the one that we have using this implementaiton.
		 */
		uint32_t _t[3] = {
			peer_ip4_be,
			local_ip4_be,
			(((uint32_t) peer_port_be) << 0) | (((uint32_t) local_port_be) << 16),
		};
		{
			uint32_t v = 0;
			{
				size_t i;
				for (i = 0; i < sizeof(_t); i++) {
					uint8_t j;
					for (j = 0; j < 8; j++) {
						if (((uint8_t *) _t)[i] & (1U << (7 - j))) {
							uint32_t _v = __iosub_rss_key_cached[i + 0] << 24 |
								__iosub_rss_key_cached[i + 1] << 16 |
								__iosub_rss_key_cached[i + 2] <<  8 |
								__iosub_rss_key_cached[i + 3] <<  0;
							if (j) {
								_v <<= j;
								_v |= __iosub_rss_key_cached[i + 4] >> (8 - j);
							}
							v ^= _v;
						}
					}
				}
			}
			return __iosub_rss_tbl_cached[v & ((1 << (31 - __builtin_clz(__iosub_num_cores))) - 1)];
		}
	}
	{ /* unused */
		(void) protocol;
		(void) opaque;
	}
}

static uint16_t iip_ops_l2_hdr_len(void *pkt, void *opaque)
{
	return sizeof(struct ethhdr);
	{ /* unused */
		(void) pkt;
		(void) opaque;
	}
}

static uint8_t *iip_ops_l2_hdr_src_ptr(void *pkt, void *opaque)
{
	return ((struct ethhdr *)(iip_ops_pkt_get_data(pkt, opaque)))->h_source;
}

static uint8_t *iip_ops_l2_hdr_dst_ptr(void *pkt, void *opaque)
{
	return ((struct ethhdr *)(iip_ops_pkt_get_data(pkt, opaque)))->h_dest;
}

static uint8_t iip_ops_l2_skip(void *pkt, void *opaque)
{
	return 0;
	{ /* unused */
		(void) pkt;
		(void) opaque;
	}
}

static uint16_t iip_ops_l2_ethertype_be(void *pkt, void *opaque)
{
	return ((struct ethhdr *)(iip_ops_pkt_get_data(pkt, opaque)))->h_proto;
}

static uint16_t iip_ops_l2_addr_len(void *opaque)
{
	return 6;
	{ /* unused */
		(void) opaque;
	}
}

static void iip_ops_l2_broadcast_addr(uint8_t bc_mac[], void *opaque)
{
	memset(bc_mac, 0xff, 6);
	{ /* unused */
		(void) opaque;
	}
}

static void iip_ops_l2_hdr_craft(void *pkt, uint8_t src[], uint8_t dst[], uint16_t ethertype_be, void *opaque)
{
	struct ethhdr *ethh = (struct ethhdr *) iip_ops_pkt_get_data(pkt, opaque);
	memcpy(ethh->h_source, src, 6);
	memcpy(ethh->h_dest, dst, 6);
	ethh->h_proto = ethertype_be;
}

static uint8_t iip_ops_arp_lhw(void *opaque)
{
	return 6;
	{ /* unused */
		(void) opaque;
	}
}

static uint8_t iip_ops_arp_lproto(void *opaque)
{
	return 4;
	{ /* unused */
		(void) opaque;
	}
}

static void __iip_buf_free(uint64_t addr, void *opaque)
{
	void **opaque_array = (void **) opaque;
	struct io_opaque *iop = (struct io_opaque *) opaque_array[0];
	__IOSUB_BUF_ADDR_ASSERT(iop, addr);
	if (--__IOSUB_BUF_REFCNT(iop, addr) == 0)
		iop->af_xdp.free_buf_addr[iop->af_xdp.free_buf_cnt++] = addr;
}

static uint64_t __iip_buf_alloc(void *opaque)
{
	void **opaque_array = (void **) opaque;
	struct io_opaque *iop = (struct io_opaque *) opaque_array[0];
	if (iop->af_xdp.free_buf_cnt) {
		uint64_t addr = iop->af_xdp.free_buf_addr[--iop->af_xdp.free_buf_cnt];
		__IOSUB_BUF_ADDR_ASSERT(iop, addr);
		assert(++__IOSUB_BUF_REFCNT(iop, addr) == 1);
		return addr;
	} else
		return UINT64_MAX;
}

static void *__iip_ops_pkt_alloc(void *opaque)
{
	void **opaque_array = (void **) opaque;
	struct io_opaque *iop = (struct io_opaque *) opaque_array[0];
	assert(iop->af_xdp.pool.free_cnt);
	{
		struct __xpb *p = iop->af_xdp.pool.free_p[--iop->af_xdp.pool.free_cnt];
		assert(p);
		return (void *) p;
	}
}

static void *iip_ops_pkt_alloc(void *opaque)
{
	struct __xpb *p = __iip_ops_pkt_alloc(opaque);
	p->addr = __iip_buf_alloc(opaque);
	assert(p->addr != UINT64_MAX);
	return p;
}

static void __iip_pkt_free(void *pkt, void *opaque)
{
	void **opaque_array = (void **) opaque;
	struct io_opaque *iop = (struct io_opaque *) opaque_array[0];
	assert(iop->af_xdp.pool.free_cnt < NUM_NETSTACK_PB);
	iop->af_xdp.pool.free_p[iop->af_xdp.pool.free_cnt++] = pkt;
}

static void iip_ops_pkt_free(void *pkt, void *opaque)
{
	assert(pkt);
	__iip_buf_free(((struct __xpb *) pkt)->addr, opaque);
	__iip_pkt_free(pkt, opaque);
}

static void *iip_ops_pkt_get_data(void *pkt, void *opaque)
{
	void **opaque_array = (void **) opaque;
	struct io_opaque *iop = (struct io_opaque *) opaque_array[0];
	return (void *) ((uintptr_t) xsk_umem__get_data(iop->af_xdp.umem_area, ((struct __xpb *) pkt)->addr) + ((struct __xpb *) pkt)->head);
}

static uint16_t iip_ops_pkt_get_len(void *pkt, void *opaque)
{
	return ((struct __xpb *) pkt)->len;
	{ /* unused */
		(void) opaque;
	}
}

static void iip_ops_pkt_set_len(void *pkt, uint16_t len, void *opaque)
{
	assert(pkt);
	((struct __xpb *) pkt)->len = len;
	{ /* unused */
		(void) opaque;
	}
}

static void iip_ops_pkt_increment_head(void *pkt, uint16_t len, void *opaque)
{
	assert(pkt);
	assert(len <= ((struct __xpb *) pkt)->len);
	((struct __xpb *) pkt)->head += len;
	((struct __xpb *) pkt)->len -= len;
	{ /* unused */
		(void) opaque;
	}
}

static void iip_ops_pkt_decrement_tail(void *pkt, uint16_t len, void *opaque)
{
	assert(pkt);
	assert(len <= ((struct __xpb *) pkt)->len);
	((struct __xpb *) pkt)->len -= len;
	{ /* unused */
		(void) opaque;
	}
}

static void *iip_ops_pkt_clone(void *pkt, void *opaque)
{
	void **opaque_array = (void **) opaque;
	struct io_opaque *iop = (struct io_opaque *) opaque_array[0];
	__IOSUB_BUF_ADDR_ASSERT(iop, ((struct __xpb *) pkt)->addr);
	assert(__IOSUB_BUF_REFCNT(iop, ((struct __xpb *) pkt)->addr));
	{
		struct __xpb *p = __iip_ops_pkt_alloc(opaque);
		p->addr = ((struct __xpb *) pkt)->addr;
		p->len = ((struct __xpb *) pkt)->len;
		p->head = ((struct __xpb *) pkt)->head;
		__IOSUB_BUF_REFCNT(iop, ((struct __xpb *) pkt)->addr)++;
		return p;
	}
}

static void iip_ops_pkt_scatter_gather_chain_append(void *pkt_head, void *pkt_tail, void *opaque __attribute__((unused)))
{
	struct __xpb *p = (struct __xpb *) pkt_head;
	while (p->next[1])
		p = p->next[1];
	p->next[1] = pkt_tail;
	((struct __xpb *) pkt_tail)->next[1] = NULL;
}

static void *iip_ops_pkt_scatter_gather_chain_get_next(void *pkt_head, void *opaque __attribute__((unused)))
{
	return ((struct __xpb *) pkt_head)->next[0];
}

static void iip_ops_l2_flush(void *opaque)
{
	void **opaque_array = (void **) opaque;
	struct io_opaque *iop = (struct io_opaque *) opaque_array[0];
	if (iop->af_xdp.eth_sent) {
		uint32_t idx;
		{
			uint32_t cnt = xsk_ring_cons__peek(iop->af_xdp.complete_ring, NUM_TX_DESC, &idx);
			if (cnt) {
				{
					uint32_t i;
					for (i = 0; i < cnt; i++)
						__iip_buf_free(*xsk_ring_cons__comp_addr(iop->af_xdp.complete_ring, idx + i), opaque);
				}
				xsk_ring_cons__release(iop->af_xdp.complete_ring, cnt);
				iop->af_xdp.eth_sent -= cnt;
			}
		}
	}
	{
		uint32_t idx;
		{
			uint32_t cnt = xsk_ring_prod__reserve(iop->af_xdp.tx_ring, iop->eth.tx.cnt, &idx);
			if (cnt) {
				uint32_t i;
				for (i = 0; i < cnt; i++) {
					struct xdp_desc *d = xsk_ring_prod__tx_desc(iop->af_xdp.tx_ring, idx + i);
					d->addr = iop->eth.tx.m[i]->addr + iop->eth.tx.m[i]->head;
					d->len = iop->eth.tx.m[i]->len;
#if 0
					if (iop->eth.tx.m[i]->next[1]) /* TODO */
						d->options |= (1UL << 0); /* XDP_PKT_CONTD */
#endif
				}
				xsk_ring_prod__submit(iop->af_xdp.tx_ring, cnt);
				if (xsk_ring_prod__needs_wakeup(iop->af_xdp.tx_ring))
					assert(sendto(xsk_socket__fd(iop->af_xdp.xsk), NULL, 0, MSG_DONTWAIT, NULL, 0) != -1);
				iop->af_xdp.eth_sent += cnt;
				iop->stat[stat_idx].eth.tx_pkt += cnt;
			}
			{
				uint32_t i;
				for (i = 0; i < cnt; i++)
					__iip_pkt_free(iop->eth.tx.m[i], opaque);
			}
			{
				uint32_t i;
				for (i = cnt; i < iop->eth.tx.cnt; i++)
					iip_ops_pkt_free(iop->eth.tx.m[i], opaque);
			}
		}
	}
	iop->eth.tx.cnt = iop->eth.tx.num_pkt = 0;
}

static void iip_ops_l2_push(void *_m, void *opaque)
{
	void **opaque_array = (void **) opaque;
	struct io_opaque *iop = (struct io_opaque *) opaque_array[0];
	{
		struct __xpb *p = (struct __xpb *) _m;
		while (p) {
			iop->eth.tx.m[iop->eth.tx.cnt++] = (struct __xpb *) p;
			p = p->next[1];
		}
		iop->eth.tx.num_pkt++;
	}
	if (ETH_TX_BATCH <= iop->eth.tx.cnt)
		iip_ops_l2_flush(opaque);
}

static uint8_t iip_ops_nic_feature_offload_tx_scatter_gather(void *opaque __attribute__((unused)))
{
	return 0; /* TODO: enable */
	{ /* unused */
		(void) opaque;
	}
}

static uint8_t iip_ops_nic_feature_offload_ip4_rx_checksum(void *opaque)
{
	return 0;
	{ /* unused */
		(void) opaque;
	}
}

static uint8_t iip_ops_nic_feature_offload_ip4_tx_checksum(void *opaque)
{
	return 0;
	{ /* unused */
		(void) opaque;
	}
}

static uint8_t iip_ops_nic_offload_ip4_rx_checksum(void *m, void *opaque)
{
	return 0;
	{ /* unused */
		(void) m;
		(void) opaque;
	}
}

static uint8_t iip_ops_nic_offload_tcp_rx_checksum(void *m, void *opaque)
{
	return 0;
	{ /* unused */
		(void) m;
		(void) opaque;
	}
}

static uint8_t iip_ops_nic_offload_udp_rx_checksum(void *m, void *opaque)
{
	return 0;
	{ /* unused */
		(void) m;
		(void) opaque;
	}
}

static void iip_ops_nic_offload_ip4_tx_checksum_mark(void *m, void *opaque)
{
	{ /* unused */
		(void) m;
		(void) opaque;
	}
}

static uint8_t iip_ops_nic_feature_offload_tcp_rx_checksum(void *opaque)
{
	return 0;
	{ /* unused */
		(void) opaque;
	}
}

static uint8_t iip_ops_nic_feature_offload_tcp_tx_checksum(void *opaque)
{
	return 0;
	{ /* unused */
		(void) opaque;
	}
}

static uint8_t iip_ops_nic_feature_offload_tcp_tx_tso(void *opaque)
{
	return 0;
	{ /* unused */
		(void) opaque;
	}
}

static void iip_ops_nic_offload_tcp_tx_checksum_mark(void *m, void *opaque)
{
	{ /* unused */
		(void) m;
		(void) opaque;
	}
}

static void iip_ops_nic_offload_tcp_tx_tso_mark(void *m, void *opaque)
{
	{ /* unused */
		(void) m;
		(void) opaque;
	}
}

static uint8_t iip_ops_nic_feature_offload_udp_rx_checksum(void *opaque)
{
	return 0;
	{ /* unused */
		(void) opaque;
	}
}

static uint8_t iip_ops_nic_feature_offload_udp_tx_checksum(void *opaque)
{
	return 0;
	{ /* unused */
		(void) opaque;
	}
}

static uint8_t iip_ops_nic_feature_offload_udp_tx_tso(void *opaque)
{
	return 0;
	{ /* unused */
		(void) opaque;
	}
}

static void iip_ops_nic_offload_udp_tx_checksum_mark(void *m, void *opaque)
{
	{ /* unused */
		(void) m;
		(void) opaque;
	}
}

static void iip_ops_nic_offload_udp_tx_tso_mark(void *m, void *opaque)
{
	{ /* unused */
		(void) m;
		(void) opaque;
	}
}

static volatile uint16_t setup_core_id = 0;

struct __thread_info {
	pthread_t th;
	uint16_t id;
	void *app_global_opaque;
};

/* thread loop */
static void *__thread_fn(void *__data)
{
	struct __thread_info *ti = (struct __thread_info *) __data;
	{
		cpu_set_t cs;
		CPU_ZERO(&cs);
		CPU_SET(__iosub_core_list[ti->id], &cs);
		assert(pthread_setaffinity_np(pthread_self(), sizeof(cs), &cs) == 0);
	}

	while (ti->id != setup_core_id)
		usleep(10000);

	{
		void *workspace = numa_alloc_local(iip_workspace_size());
		assert(workspace);
		{
			uint8_t *_premem[2];
			{
				assert((_premem[0] = (uint8_t *) numa_alloc_local(iip_pb_size() * NUM_NETSTACK_PB)) != NULL);
				{ /* associate memory for packet representation structure */
					uint32_t i;
					for (i = 0; i < NUM_NETSTACK_PB; i++)
						iip_add_pb(workspace, &_premem[0][i * iip_pb_size()]);
				}
				assert((_premem[1] = numa_alloc_local(iip_tcp_conn_size() * NUM_NETSTACK_TCP_CONN)) != NULL);
				{ /* associate memory for tcp connection */
					uint16_t i;
					for (i = 0; i < NUM_NETSTACK_TCP_CONN; i++)
						iip_add_tcp_conn(workspace, &_premem[1][i * iip_tcp_conn_size()]);
				}
				{ /* associate memory for tcp connection */
					uint16_t i;
					for (i = 0; i < NUM_NETSTACK_PB; i++)
						io_opaque[ti->id].af_xdp.pool.free_p[io_opaque[ti->id].af_xdp.pool.free_cnt++] = &io_opaque[ti->id].af_xdp.pool.p[i];
				}
				{ /* make a queue for buffer memory */
					uint16_t i;
					for (i = 0; i < NUM_BUF; i++)
						io_opaque[ti->id].af_xdp.free_buf_addr[io_opaque[ti->id].af_xdp.free_buf_cnt++] = BUF_SIZE * i;
				}
				printf("rx-desc %u tx-desc %u rx-batch %u tx-batch %u buf-size %u head-room %u\n", NUM_RX_DESC, NUM_TX_DESC, ETH_RX_BATCH, ETH_TX_BATCH, BUF_SIZE, XSK_UMEM__DEFAULT_FRAME_HEADROOM);
				{ /* instantiate xdp socket */
					struct xsk_socket *xsk;
					void *umem_area;
					struct xsk_umem *umem;
					struct xsk_ring_prod fill_ring = { 0 };
					struct xsk_ring_cons complete_ring = { 0 };
					{
						assert((umem_area = numa_alloc_local(BUF_SIZE * NUM_BUF)) != NULL);
						{
							struct xsk_umem_config cfg = {
								.fill_size = NUM_RX_DESC,
								.comp_size = NUM_TX_DESC,
								.frame_size = BUF_SIZE,
								.frame_headroom = XSK_UMEM__DEFAULT_FRAME_HEADROOM,
								.flags = 0,
							};
							xsk_umem__create(&umem, umem_area, BUF_SIZE * NUM_BUF,
								&fill_ring, &complete_ring, &cfg);
						}
					}
					{
						struct xsk_ring_cons rx_ring;
						struct xsk_ring_prod tx_ring;
						{
							struct xsk_socket_config cfg = {
								.rx_size = NUM_RX_DESC,
								.tx_size = NUM_TX_DESC,
								.libbpf_flags = 0,
								.xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_DRV_MODE,
								.bind_flags = XDP_USE_NEED_WAKEUP | XDP_ZEROCOPY /* | XDP_USE_SG */,
							};
							assert(!xsk_socket__create(&xsk, __iosub_ifname, ti->id, umem, &rx_ring, &tx_ring, &cfg));
						}
						if (__IOSUB_BUSY_POLL_SOCK) {
							{
								uint32_t val = 1;
								assert(setsockopt(xsk_socket__fd(xsk), SOL_SOCKET, SO_PREFER_BUSY_POLL, &val, sizeof(val)) != -1);
							}
							{
								uint32_t val = 20;
								assert(setsockopt(xsk_socket__fd(xsk), SOL_SOCKET, SO_BUSY_POLL, &val, sizeof(val)) != -1);
							}
							{
								uint32_t val = ETH_RX_BATCH;
								assert(setsockopt(xsk_socket__fd(xsk), SOL_SOCKET, SO_BUSY_POLL_BUDGET, &val, sizeof(val)) != -1);
							}
						}

						setup_core_id++;

						io_opaque[ti->id].af_xdp.xsk = xsk;
						io_opaque[ti->id].af_xdp.umem_area = umem_area;
						io_opaque[ti->id].af_xdp.complete_ring = &complete_ring;
						io_opaque[ti->id].af_xdp.tx_ring = &tx_ring;

						{
							uint32_t idx;
							{
								uint32_t _cnt;
								_cnt = xsk_ring_prod__reserve(&fill_ring, NUM_RX_DESC, &idx);
								assert(_cnt == NUM_RX_DESC);
								{
									uint32_t i;
									for (i = 0; i < _cnt; i++) {
										{
											void *opaque[3] = { (void *) &io_opaque[ti->id], ti->app_global_opaque, NULL, };
											*xsk_ring_prod__fill_addr(&fill_ring, idx + i) = __iip_buf_alloc(opaque);
										}
										assert(*xsk_ring_prod__fill_addr(&fill_ring, idx + i) != UINT64_MAX);
									}
								}
								xsk_ring_prod__submit(&fill_ring, _cnt);
								if (xsk_ring_prod__needs_wakeup(&fill_ring))
									assert(sendto(xsk_socket__fd(xsk), NULL, 0, MSG_DONTWAIT, NULL, 0) != -1);
							}
						}

						while (setup_core_id != __iosub_num_cores)
							usleep(100000);

						{ /* call app thread init */
							void *opaque[3] = { (void *) &io_opaque[ti->id], ti->app_global_opaque, NULL, };
							{
								opaque[2] = __app_thread_init(workspace, ti->id, opaque);
								{
									uint64_t prev_print = 0;
									do {
										uint32_t next_us = __iosub_max_poll_wait_ms * 1000;
										{
											struct __xpb *m[ETH_RX_BATCH] = { 0 };
											uint32_t cnt = 0;
											{
												uint32_t idx;
												cnt = xsk_ring_cons__peek(&rx_ring, ETH_RX_BATCH, &idx);
												if (cnt) {
													{
														uint32_t i;
														for (i = 0; i < cnt; i++) {
															const struct xdp_desc *d = xsk_ring_cons__rx_desc(&rx_ring, idx + i);
															assert((m[i] = __iip_ops_pkt_alloc(opaque)) != NULL);
															m[i]->addr = d->addr;
															m[i]->len = d->len;
															__IOSUB_BUF_ADDR_ASSERT(&io_opaque[ti->id], d->addr);
															assert(__IOSUB_BUF_REFCNT(&io_opaque[ti->id], d->addr) == 1);
														}
													}
													{
														uint32_t __idx;
														while (cnt != xsk_ring_prod__reserve(&fill_ring, cnt, &__idx)) {
															if (__IOSUB_BUSY_POLL_SOCK || xsk_ring_prod__needs_wakeup(&fill_ring))
																assert(recvfrom(xsk_socket__fd(xsk), NULL, 0, MSG_DONTWAIT, NULL, 0) != -1);
														}
														{
															uint32_t i;
															for (i = 0; i < cnt; i++) {
																uint64_t addr = __iip_buf_alloc(opaque);
																assert(addr != UINT64_MAX);
																__IOSUB_BUF_ADDR_ASSERT(&io_opaque[ti->id], addr);
																assert(__IOSUB_BUF_REFCNT(&io_opaque[ti->id], addr) == 1);
																*xsk_ring_prod__fill_addr(&fill_ring, __idx + i) = addr;
															}
														}
													}
													xsk_ring_cons__release(&rx_ring, cnt);
													xsk_ring_prod__submit(&fill_ring, cnt);
													io_opaque[ti->id].stat[stat_idx].eth.rx_pkt += cnt;
													next_us = 0;
												} else {
													if (__IOSUB_BUSY_POLL_SOCK || xsk_ring_prod__needs_wakeup(&fill_ring))
														assert(recvfrom(xsk_socket__fd(xsk), NULL, 0, MSG_DONTWAIT, NULL, 0) != -1);
												}
											}
											{ /* execute network stack */
												uint32_t _next_us = 1000000U;
												iip_run(workspace, mac_addr, ip4_addr_be, (void **) m, cnt, &_next_us, opaque);
												next_us = _next_us < next_us ? _next_us : next_us;
											}
										}
										{
											uint32_t _next_us = 1000000U;
											__app_loop(workspace, mac_addr, ip4_addr_be, &_next_us, opaque);
											next_us = _next_us < next_us ? _next_us : next_us;
										}
										if (!ti->id) {
											struct timespec ts;
											assert(!clock_gettime(CLOCK_REALTIME, &ts));
											if (prev_print + 1000000000UL < ts.tv_sec * 1000000000UL + ts.tv_nsec) {
#if 0
												stat_idx = (stat_idx ? 0 : 1);
												asm volatile ("" ::: "memory");
												{
													uint64_t total_rx = 0, total_tx = 0;
													{
														uint16_t i;
														for (i = 0; i < __iosub_num_cores; i++) {
															printf("\x1b[33mqueue[%u]: rx %lu drop %lu tx %lu fail %lu\n\x1b[39m",
																	i,
																	io_opaque[i].stat[stat_idx ? 0 : 1].eth.rx_pkt,
																	io_opaque[i].stat[stat_idx ? 0 : 1].eth.rx_drop,
																	io_opaque[i].stat[stat_idx ? 0 : 1].eth.tx_pkt,
																	io_opaque[i].stat[stat_idx ? 0 : 1].eth.tx_fail);
															total_rx += io_opaque[i].stat[stat_idx ? 0 : 1].eth.rx_pkt;
															total_tx += io_opaque[i].stat[stat_idx ? 0 : 1].eth.tx_pkt;
															memset(&io_opaque[i].stat[stat_idx ? 0 : 1], 0, sizeof(io_opaque[i].stat[stat_idx ? 0 : 1]));
														}
													}
													printf("\x1b[33meth total: rx %lu tx %lu\n\x1b[39m", total_rx, total_tx);
												}
#endif
												prev_print = ts.tv_sec * 1000000000UL + ts.tv_nsec;
											}
										}
										if (next_us) {
											struct pollfd pollfd = {
												.fd = xsk_socket__fd(xsk),
												.events = POLLIN,
											};
											assert(poll(&pollfd, 1, (next_us / 1000)) != -1);
										}
									} while (!__app_should_stop(opaque));
								}
							}
						}
					}
				}
			}
			numa_free(_premem[1], iip_tcp_conn_size() * NUM_NETSTACK_TCP_CONN);
			numa_free(_premem[0], iip_pb_size() * NUM_NETSTACK_PB);
		}
	}

	numa_free(io_opaque[ti->id].af_xdp.umem_area, BUF_SIZE * NUM_BUF);

	pthread_exit(NULL);
}

static int __iosub_main(int argc, char *const *argv)
{
	{
		int ch;
		while ((ch = getopt(argc, argv, "e:i:l:")) != -1) {
			switch (ch) {
			case 'e':
				assert(sscanf(optarg, "%d", &__iosub_max_poll_wait_ms) == 1);
				break;
			case 'i':
				__iosub_ifname = optarg;
				break;
			case 'l':
				{
					ssize_t num_comma = 0, num_hyphen = 0;
					{
						size_t i;
						for (i = 0; i < strlen(optarg); i++) {
							switch (optarg[i]) {
							case ',':
								num_comma++;
								break;
							case '-':
								num_hyphen++;
								break;
							}
						}
					}
					if (num_hyphen) {
						assert(num_hyphen == 1);
						assert(!num_comma);
						{
							char *m;
							assert((m = strdup(optarg)) != NULL);
							{
								size_t i;
								for (i = 0; i < strlen(optarg); i++) {
									if (m[i] == '-') {
										m[i] = '\0';
										break;
									}
								}
								assert(i != strlen(optarg) - 1 && i != strlen(optarg));
								{
									uint16_t from = atoi(&m[0]), to = atoi(&m[i + 1]);
									assert(from <= to);
									{
										uint16_t j, k;
										for (j = 0, k = from; k <= to; j++, k++)
											__iosub_core_list[j] = k;
										__iosub_num_cores = j;
									}
								}
							}
							free(m);
						}
					} else if (num_comma) {
						assert(num_comma + 1 < __IOSUB_MAX_CORE);
						{
							char *m;
							assert((m = strdup(optarg)) != NULL);
							{
								size_t i, j, k;
								for (i = 0, j = 0, k = 0; i < strlen(optarg) + 1; i++) {
									if (i == strlen(optarg) || m[i] == ',') {
										m[i] = '\0';
										if (j != i)
											__iosub_core_list[k++] = atoi(&m[j]);
										j = i + 1;
									}
									if (i == strlen(optarg))
										break;
								}
								assert(k);
								__iosub_num_cores = k;
							}
							free(m);
						}
					} else {
						__iosub_core_list[0] = atoi(optarg);
						__iosub_num_cores = 1;
					}
				}
				break;
			default:
				assert(0);
				break;
			}
		}
	}

	assert(__iosub_ifname);
	assert(0 < __iosub_num_cores && __iosub_num_cores < MAX_THREAD);

	{
		int fd;
		assert((fd = socket(AF_INET, SOCK_DGRAM, 0)) != -1);
		{
			struct ifreq ifr = { 0 };
			strncpy(ifr.ifr_name, __iosub_ifname, sizeof(ifr.ifr_name) - 1);
			assert(!ioctl(fd, SIOCGIFHWADDR, &ifr));
			memcpy(mac_addr, ifr.ifr_hwaddr.sa_data, sizeof(mac_addr));
		}
		{
			struct ifreq ifr = {
				.ifr_addr.sa_family = AF_INET,
			};
			strncpy(ifr.ifr_name, __iosub_ifname, sizeof(ifr.ifr_name) - 1);
			assert(!ioctl(fd, SIOCGIFADDR, &ifr));
			ip4_addr_be = ((struct sockaddr_in *) &ifr.ifr_addr)->sin_addr.s_addr;
		}
		close(fd);
	}
	printf("mac addr %02x:%02x:%02x:%02x:%02x:%02x\n",
			mac_addr[0],
			mac_addr[1],
			mac_addr[2],
			mac_addr[3],
			mac_addr[4],
			mac_addr[5]);
	printf("ip addr %u.%u.%u.%u\n",
			(ip4_addr_be >>  0) & 0x0ff,
			(ip4_addr_be >>  8) & 0x0ff,
			(ip4_addr_be >> 16) & 0x0ff,
			(ip4_addr_be >> 24) & 0x0ff);
	{
		uint16_t i;
		for (i = 0; i < __iosub_num_cores; i++) {
			printf("core map[%u]: %u\n", i, __iosub_core_list[i]);
		}
	}

	{
		void *app_global_opaque = __app_init(argc, argv);
		{
			struct __thread_info ti[MAX_THREAD];
			{
				uint16_t i;
				for (i = 0; i < __iosub_num_cores; i++) {
					ti[i].id = i;
					ti[i].app_global_opaque = app_global_opaque;
					assert(!pthread_create(&ti[i].th, NULL, __thread_fn, &ti[i]));
				}
			}
			{
				uint16_t i;
				for (i = 0; i < __iosub_num_cores; i++)
					assert(!pthread_join(ti[i].th, NULL));
			}
		}
		__app_exit(app_global_opaque);
	}

	printf("Done.\n");

	return 0;
}
