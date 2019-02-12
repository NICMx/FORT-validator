#ifndef SRC_NID_H_
#define SRC_NID_H_

int nid_init(void);

int nid_rpkiManifest(void);
int nid_signedObject(void);
int nid_rpkiNotify(void);
int nid_certPolicyRpki(void);
int nid_certPolicyRpkiV2(void);
int nid_ipAddrBlocksv2(void);
int nid_autonomousSysIdsv2(void);

#endif /* SRC_NID_H_ */
