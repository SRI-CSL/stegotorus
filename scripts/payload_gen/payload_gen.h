
#ifndef _PAYLOAD_GEN_H
#define _PAYLOAD_GEN_H

/* three files:
   server_data, client data, protocol data
*/



#define NO_NEXT_STATE -1

typedef int SID;
typedef short PacketType;
typedef short StateFlag;

#define TYPE_SERVICE_DATA 0x1
#define TYPE_HTTP_REQUEST 0x2
#define TYPE_HTTP_RESPONSE 0x4
#define BEGIN_STATE_FLG 0x1
#define END_STATE_FLG 0x2




/* struct for reading in the payload_gen dump file */
typedef struct {
  PacketType ptype;
  int length;
  ushort port; /* network format */
}pentry_header;




typedef struct service_state {
  SID id;
  PacketType data_type;
  SID next_state;
  //  double* probabilities;
  StateFlag flg;
  int dir;
}state;



#endif
