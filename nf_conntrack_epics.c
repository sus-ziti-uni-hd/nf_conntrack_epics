#include <linux/kernel.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/udp.h>

#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_helper.h>
#include <net/netfilter/nf_conntrack_expect.h>

MODULE_AUTHOR("Michael Ritzert <michael.ritzert@ziti.uni-heidelberg.de>");
MODULE_DESCRIPTION("EPICS NF connection tracking helper");
MODULE_LICENSE("GPL");
MODULE_ALIAS("ip_conntrack_epics");
MODULE_ALIAS_NFCT_HELPER("epics");

struct ca_header {
    __be16 command;
    __be16 payloadSize;
    __be16 dataType;
    __be16 dataCount;
    __be32 parameter1;
    __be32 parameter2;
};

static int epics_conntrack_search_reply_help(struct sk_buff *skb,
           unsigned int protoff,
           struct nf_conn *ct,
           enum ip_conntrack_info ctinfo);

static int epics_conntrack_search_request_help(struct sk_buff *skb,
           unsigned int protoff,
           struct nf_conn *ct,
           enum ip_conntrack_info ctinfo);

static const struct nf_conntrack_expect_policy epics_exp_policy = {
   .max_expected = 40,
   .timeout      = 5
};

static struct nf_conntrack_helper request_helper __read_mostly = {
   .name                   = "epics_request",
   .tuple.src.l3num        = NFPROTO_IPV4,
   .tuple.dst.protonum     = IPPROTO_UDP,
   .me                     = THIS_MODULE,
   .help                   = epics_conntrack_search_request_help,
   .expect_policy          = &epics_exp_policy,
};

static const struct nf_conntrack_expect_policy epics_exp_policy2 = {
   .max_expected  = 40,
   .timeout       = 5
};

static struct nf_conntrack_helper reply_helper __read_mostly = {
   .name                   = "epics_reply",
   .me                     = THIS_MODULE,
   .tuple.src.l3num        = NFPROTO_IPV4,
   .tuple.dst.protonum     = IPPROTO_UDP,
   .help                   = epics_conntrack_search_reply_help,
   .expect_policy          = &epics_exp_policy2,
};


int handle_search_request(struct sk_buff *skb,
            unsigned int protoff,
            struct nf_conn *ct,
            enum ip_conntrack_info ctinfo,
            unsigned int timeout,
            struct nf_conntrack_helper *reply_helper)
{
   /* we have an incoming search request.
      set up to catch the reply that will go back to the source address/port
    */
   struct nf_conntrack_expect *exp;
   struct nf_conn_help *help = nfct_help(ct);

   exp = nf_ct_expect_alloc(ct);
   if (exp == NULL)
      goto out;

   exp->tuple                = ct->tuplehash[IP_CT_DIR_REPLY].tuple;
   exp->tuple.src.u.udp.port = help->helper->tuple.src.u.udp.port;
   /* cannot get this since the incoming packet goes to the broadcast address... */
   exp->mask.src.u3.ip       = htonl(0x00000000);
   exp->mask.src.u.udp.port  = htons(0xFFFF);

   /*pr_info("filtering for %08x:%d, *:%d", exp->tuple.dst.u3.ip, be16_to_cpu(exp->tuple.dst.u.udp.port), be16_to_cpu(exp->tuple.src.u.udp.port));*/

   exp->expectfn    = NULL;
   exp->flags       = NF_CT_EXPECT_PERMANENT;
   exp->class       = NF_CT_EXPECT_CLASS_DEFAULT;
   exp->helper      = reply_helper;

   nf_ct_expect_related(exp);
   nf_ct_expect_put(exp);

   nf_ct_refresh(ct, skb, timeout * HZ);
out:
   return NF_ACCEPT;
}


static unsigned short ca1_port __read_mostly = 5064U;
module_param(ca1_port, ushort, S_IRUSR);
MODULE_PARM_DESC(ca1_port, "EPICS CA1 port number");

static int epics_conntrack_search_request_help(struct sk_buff *skb,
           unsigned int protoff,
           struct nf_conn *ct,
           enum ip_conntrack_info ctinfo)
{
   if (skb->sk) {
      /* locally generated */
      /* => set up to allow the incoming reply */
      return nf_conntrack_broadcast_help(skb, protoff, ct, ctinfo, 5 /* timeout */);
   }
   /* else (incoming packet) */
   /* => set up to capture the next packet */
   return handle_search_request(skb, protoff, ct, ctinfo, 5 /* timeout */, &reply_helper);
}

static int epics_conntrack_search_reply_help(struct sk_buff *skb,
           unsigned int protoff,
           struct nf_conn *ct,
           enum ip_conntrack_info ctinfo)
{
   struct ca_header hdr;
   struct nf_conntrack_expect *exp;
   struct nf_conntrack_tuple *tuple;
   __u16 port;

   int offset = sizeof(struct iphdr) + sizeof(struct udphdr);
   while (offset + 16 <= skb->len) {
      skb_copy_bits(skb, offset, &hdr, sizeof(hdr));
/*    pr_info("size: %d, command: %d, size: %d, datatype: %d", skb->len, be16_to_cpu(hdr.command), be16_to_cpu(hdr.payloadSize), be16_to_cpu(hdr.dataType));*/
      if ((be16_to_cpu(hdr.command) == 0x06) && (hdr.parameter1 == 0xFFFFFFFF)) {
         port = be16_to_cpu(hdr.dataType);
         if (port < 1024U) {
            pr_warning("Not allowing port %d < 1024 in.", port);
            break;
         }
         tuple = &ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple;
         exp = nf_ct_expect_alloc(ct);
/*       pr_info("expecting TCP %08x to %08x:%d", tuple->dst.u3.ip, tuple->src.u3.ip, hdr.m_dataType); */
         nf_ct_expect_init(exp, NF_CT_EXPECT_CLASS_DEFAULT,
               nf_ct_l3num(ct),
               &tuple->dst.u3, &tuple->src.u3,
               IPPROTO_TCP, NULL, &hdr.dataType /* already big endian */);
         if (nf_ct_expect_related(exp) != 0) {
            pr_warning("expect_related failed");
         } else {
             nf_ct_expect_put(exp);
         }
         /* next reply would only be for the same port, since it's from the
          * same server. */
         break;
      }
      /* move to next command in packet */
      offset += 16;
      offset += be16_to_cpu(hdr.payloadSize);
   }
   return NF_ACCEPT;
}

static int __init nf_conntrack_epics_init(void)
{
   int ret;
   BUG_ON(sizeof(struct ca_header) != 16);

   /* this is a bit strange. wrong way round to what I'd expect. */
   /* destination port 5064 (ca1_port) */
   request_helper.tuple.src.u.udp.port = cpu_to_be16(ca1_port);
   ret = nf_conntrack_helper_register(&request_helper);
   if (ret != 0) return ret;
   pr_info("EPICS NF handlers successfully registered.");
   return ret;
}

static void nf_conntrack_epics_fini(void)
{
   nf_conntrack_helper_unregister(&request_helper);
}

module_init(nf_conntrack_epics_init);
module_exit(nf_conntrack_epics_fini);
