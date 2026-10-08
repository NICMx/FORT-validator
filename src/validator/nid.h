#ifndef SRC_NID_H_
#define SRC_NID_H_

int nid_init(void);
void nid_destroy(void);

int nid_ct_roa(void);
int nid_ct_mft(void);
int nid_ct_gbr(void);
int nid_ad_mft(void);
int nid_ad_so(void);
int nid_ad_notify(void);
int nid_certPolicyRpki(void);
int nid_certPolicyRpkiV2(void);
int nid_ipAddrBlocksv2(void);
int nid_autonomousSysIdsv2(void);
int nid_bgpsecRouter(void);

#endif /* SRC_NID_H_ */
