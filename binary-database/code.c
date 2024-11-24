#include "out.h"



// WARNING: Function: __x86.get_pc_thunk.bx replaced with injection: get_pc_thunk_bx

int _init(EVP_PKEY_CTX *ctx)

{
  int iVar1;
  
  iVar1 = __gmon_start__();
  return iVar1;
}



void FUN_08049030(void)

{
  (*(code *)(undefined *)0x0)();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int strcmp(char *__s1,char *__s2)

{
  int iVar1;
  
  iVar1 = strcmp(__s1,__s2);
  return iVar1;
}



void __libc_start_main(void)

{
  __libc_start_main();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

ssize_t read(int __fd,void *__buf,size_t __nbytes)

{
  ssize_t sVar1;
  
  sVar1 = read(__fd,__buf,__nbytes);
  return sVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int fflush(FILE *__stream)

{
  int iVar1;
  
  iVar1 = fflush(__stream);
  return iVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void * memcpy(void *__dest,void *__src,size_t __n)

{
  void *pvVar1;
  
  pvVar1 = memcpy(__dest,__src,__n);
  return pvVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

char * fgets(char *__s,int __n,FILE *__stream)

{
  char *pcVar1;
  
  pcVar1 = fgets(__s,__n,__stream);
  return pcVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int fclose(FILE *__stream)

{
  int iVar1;
  
  iVar1 = fclose(__stream);
  return iVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

uint16_t htons(uint16_t __hostshort)

{
  uint16_t uVar1;
  
  uVar1 = htons(__hostshort);
  return uVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int accept(int __fd,sockaddr *__addr,socklen_t *__addr_len)

{
  int iVar1;
  
  iVar1 = accept(__fd,__addr,__addr_len);
  return iVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

size_t fwrite(void *__ptr,size_t __size,size_t __n,FILE *__s)

{
  size_t sVar1;
  
  sVar1 = fwrite(__ptr,__size,__n,__s);
  return sVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

size_t fread(void *__ptr,size_t __size,size_t __n,FILE *__stream)

{
  size_t sVar1;
  
  sVar1 = fread(__ptr,__size,__n,__stream);
  return sVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

char * strcpy(char *__dest,char *__src)

{
  char *pcVar1;
  
  pcVar1 = strcpy(__dest,__src);
  return pcVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int puts(char *__s)

{
  int iVar1;
  
  iVar1 = puts(__s);
  return iVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void exit(int __status)

{
                    // WARNING: Subroutine does not return
  exit(__status);
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int fprintf(FILE *__stream,char *__format,...)

{
  int iVar1;
  
  iVar1 = fprintf(__stream,__format);
  return iVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

ssize_t write(int __fd,void *__buf,size_t __n)

{
  ssize_t sVar1;
  
  sVar1 = write(__fd,__buf,__n);
  return sVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int bind(int __fd,sockaddr *__addr,socklen_t __len)

{
  int iVar1;
  
  iVar1 = bind(__fd,__addr,__len);
  return iVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

FILE * fopen(char *__filename,char *__modes)

{
  FILE *pFVar1;
  
  pFVar1 = fopen(__filename,__modes);
  return pFVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void * memset(void *__s,int __c,size_t __n)

{
  void *pvVar1;
  
  pvVar1 = memset(__s,__c,__n);
  return pvVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int * __errno_location(void)

{
  int *piVar1;
  
  piVar1 = __errno_location();
  return piVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int listen(int __fd,int __n)

{
  int iVar1;
  
  iVar1 = listen(__fd,__n);
  return iVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int fputc(int __c,FILE *__stream)

{
  int iVar1;
  
  iVar1 = fputc(__c,__stream);
  return iVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int socket(int __domain,int __type,int __protocol)

{
  int iVar1;
  
  iVar1 = socket(__domain,__type,__protocol);
  return iVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

in_addr_t inet_addr(char *__cp)

{
  in_addr_t iVar1;
  
  iVar1 = inet_addr(__cp);
  return iVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int strncmp(char *__s1,char *__s2,size_t __n)

{
  int iVar1;
  
  iVar1 = strncmp(__s1,__s2,__n);
  return iVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

long strtol(char *__nptr,char **__endptr,int __base)

{
  long lVar1;
  
  lVar1 = strtol(__nptr,__endptr,__base);
  return lVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int close(int __fd)

{
  int iVar1;
  
  iVar1 = close(__fd);
  return iVar1;
}



// WARNING: Function: __i686.get_pc_thunk.bx replaced with injection: get_pc_thunk_bx

void processEntry _start(undefined4 param_1,undefined4 param_2)

{
  undefined auStack_4 [4];
  
  __libc_start_main(main,param_2,&stack0x00000004,0,0,param_1,auStack_4);
  do {
                    // WARNING: Do nothing block with infinite loop
  } while( true );
}



// WARNING: This is an inlined function

void __i686_get_pc_thunk_bx(void)

{
  return;
}



void _dl_relocate_static_pie(void)

{
  return;
}



// WARNING: This is an inlined function

void __x86_get_pc_thunk_bx(void)

{
  return;
}



// WARNING: Removing unreachable block (ram,0x0804925c)
// WARNING: Removing unreachable block (ram,0x08049265)

void deregister_tm_clones(void)

{
  return;
}



// WARNING: Removing unreachable block (ram,0x080492a8)
// WARNING: Removing unreachable block (ram,0x080492b1)

void register_tm_clones(void)

{
  return;
}



void __do_global_dtors_aux(void)

{
  if (completed_0 == '\0') {
    deregister_tm_clones();
    completed_0 = 1;
    return;
  }
  return;
}



void frame_dummy(void)

{
  register_tm_clones();
  return;
}



int recv_bytes(int fd,char *buf,uint8_t n)

{
  ssize_t sVar1;
  uint8_t n_local;
  ssize_t ret;
  ssize_t bytes_read;
  
  n_local = n;
  bytes_read = 0;
  while ((sVar1 = bytes_read, n_local != '\0' &&
         (sVar1 = read(fd,buf + bytes_read,(uint)n_local), 0 < sVar1))) {
    n_local = n_local - (char)sVar1;
    bytes_read = bytes_read + sVar1;
  }
  return sVar1;
}



int send_bytes(int fd,char *buf,uint8_t n)

{
  ssize_t sVar1;
  uint8_t n_local;
  ssize_t ret;
  ssize_t bytes_written;
  
  n_local = n;
  bytes_written = 0;
  while ((sVar1 = bytes_written, n_local != '\0' &&
         (sVar1 = write(fd,buf + bytes_written,(uint)n_local), 0 < sVar1))) {
    n_local = n_local - (char)sVar1;
    bytes_written = bytes_written + sVar1;
  }
  return sVar1;
}



// WARNING: Unknown calling convention

void dbgfprint(FILE *file,char *buf,ssize_t len)

{
  int i;
  
  for (i = 0; i < len; i = i + 1) {
    fprintf((FILE *)file,"%02X ",(uint)(byte)buf[i]);
  }
  fputc(10,(FILE *)file);
  return;
}



// WARNING: Unknown calling convention

int db_retrieve(char *key,int *data_type,char *out_data)

{
  int iVar1;
  int i;
  
  i = 0;
  while( true ) {
    if (0x2a < i) {
      return -2;
    }
    if ((db_entries[i].key[0] != '\0') && (iVar1 = strncmp(key,db_entries[i].key,0x10), iVar1 == 0))
    break;
    i = i + 1;
  }
  if (user_privileges < db_entries[i].priv) {
    return -0xd;
  }
  *data_type = db_entries[i].type;
  memcpy(out_data,&db_entries[i].data,0x25);
  return 1;
}



// WARNING: Unknown calling convention

int db_store(char *key,int data_type,char *data)

{
  int iVar1;
  int found_empty;
  int i;
  
  found_empty = -1;
  i = 0;
  do {
    if (0x2a < i) {
      if (found_empty < 0) {
        iVar1 = -0xc;
      }
      else {
        strcpy(db_entries[found_empty].key,key);
        db_entries[found_empty].type = data_type;
        db_entries[found_empty].priv = user_privileges;
        memcpy(&db_entries[found_empty].data,data,0x25);
        iVar1 = 1;
      }
      return iVar1;
    }
    if (db_entries[i].key[0] == '\0') {
      if (found_empty < 0) {
        found_empty = i;
      }
    }
    else {
      iVar1 = strncmp(key,db_entries[i].key,0x10);
      if (iVar1 == 0) {
        if (user_privileges < db_entries[i].priv) {
          return -0xd;
        }
        db_entries[i].type = data_type;
        db_entries[i].priv = user_privileges;
        memcpy(&db_entries[i].data,data,0x25);
        return 0;
      }
    }
    i = i + 1;
  } while( true );
}



// WARNING: Unknown calling convention

int db_delete(char *key)

{
  int iVar1;
  int found_empty;
  int i;
  
  i = 0;
  while( true ) {
    if (0x2a < i) {
      return 0;
    }
    if ((db_entries[i].key[0] != '\0') && (iVar1 = strncmp(key,db_entries[i].key,0x10), iVar1 == 0))
    break;
    i = i + 1;
  }
  memset(db_entries + i,0,0x3d);
  return 1;
}



// WARNING: Unknown calling convention

int db_load_from_file(void)

{
  int iVar1;
  size_t sVar2;
  int entry_len;
  uint8_t count;
  FILE *f;
  int i;
  
  f = (FILE *)fopen("init.db","r");
  if ((FILE *)f == (FILE *)0x0) {
    fwrite("WARN: Could not open database file!\n",1,0x24,stderr);
    iVar1 = -0xd;
  }
  else {
    count = '\0';
    sVar2 = fread(&count,1,1,(FILE *)f);
    if (sVar2 == 0) {
      iVar1 = 0;
    }
    else {
      for (i = 0; i < (int)(uint)count; i = i + 1) {
        sVar2 = fread(&entry_len,4,1,(FILE *)f);
        if ((sVar2 == 0) || (sVar2 = fread(db_entries + i,entry_len,1,(FILE *)f), sVar2 == 0)) {
          fprintf(stderr,"WARN: database entry %i is corrupted!\n",i);
          return -0x16;
        }
      }
      fwrite("Database init.db successfully loaded!\n",1,0x26,stderr);
      iVar1 = 1;
    }
  }
  return iVar1;
}



// WARNING: Unknown calling convention

void db_first_flag(uint magic)

{
  FILE *__stream;
  char buf [100];
  FILE *f;
  
  if (magic != global_magix) {
    puts("You shall not pass!");
    fflush(stdout);
                    // WARNING: Subroutine does not return
    exit(2);
  }
  __stream = fopen("flag","r");
  if (__stream == (FILE *)0x0) {
    puts(
        "File opening failed!\nNote: there is no flag available locally, try it on the remote server!"
        );
    fflush(stdout);
                    // WARNING: Subroutine does not return
    exit(1);
  }
  fgets(buf,99,__stream);
  fclose(__stream);
  if (magic != global_magix) {
    puts("Did you just bypass the first magic check? Flag denied! ");
    fflush(stdout);
                    // WARNING: Subroutine does not return
    exit(2);
  }
  puts(buf);
                    // WARNING: Subroutine does not return
  exit(0);
}



// WARNING: Unknown calling convention

int process_request(db_req_pkt *rpkt,db_reply_pkt *reply)

{
  db_actions dVar1;
  int iVar2;
  int tmp1;
  int ret;
  
  tmp1 = 0;
  ret = 0;
  dVar1 = rpkt->action;
  if (dVar1 == DB_DEBUG) {
    reply->type = 99;
    (reply->data).i = (int)rpkt;
    return 1;
  }
  if (dVar1 < 100) {
    if (dVar1 == DB_DELETE) {
      iVar2 = db_delete(rpkt->key);
      return iVar2;
    }
    if (dVar1 < 4) {
      if (dVar1 == DB_STORE) {
        iVar2 = db_store(rpkt->key,rpkt->type,(rpkt->data).s);
        return iVar2;
      }
      if (dVar1 < DB_DELETE) {
        if (dVar1 == DB_NOOP) {
          return 0;
        }
        if (dVar1 == DB_RETRIEVE) {
          iVar2 = db_retrieve(rpkt->key,&tmp1,(reply->data).s);
          if (iVar2 < 0) {
            return iVar2;
          }
          reply->type = tmp1;
          return iVar2;
        }
      }
    }
  }
  return -0x2a;
}



// WARNING: Unknown calling convention

int process_loop(void)

{
  uint uVar1;
  undefined4 *puVar2;
  db_reply_pkt reply;
  char rbuf [46];
  int len;
  int ret;
  
  ret = 0;
  len = 0;
  reply.status = 0;
  reply.data._33_4_ = 0;
  puVar2 = (undefined4 *)((int)&reply.status + 3);
  uVar1 = (uint)(rbuf + -(int)puVar2) >> 2;
  for (; uVar1 != 0; uVar1 = uVar1 - 1) {
    *puVar2 = 0;
    puVar2 = puVar2 + 1;
  }
  do {
    ret = recv_bytes(recv_fd,(char *)&len,'\x04');
    if (ret < 1) {
LAB_08049b36:
      send_bytes(send_fd,(char *)&len,'\x04');
      send_bytes(send_fd,(char *)&reply,(uint8_t)len);
      return ret;
    }
    if (0x3c < len) {
      ret = -0x4a;
      goto LAB_08049b36;
    }
    if (len == 0) {
      return 0;
    }
    ret = recv_bytes(recv_fd,rbuf,(uint8_t)len);
    if (ret < 0) goto LAB_08049b36;
    reply.status = process_request((db_req_pkt *)rbuf,&reply);
    if (reply.status < 0) {
      len = 4;
    }
    else {
      len = 0x2d;
    }
    ret = reply.status;
    send_bytes(send_fd,(char *)&len,'\x04');
    send_bytes(send_fd,(char *)&reply,(uint8_t)len);
  } while( true );
}



// WARNING: Unknown calling convention

int main(int argc,char **argv)

{
  int iVar1;
  int *piVar2;
  bool bVar3;
  sockaddr local_54;
  sockaddr local_44;
  socklen_t local_34;
  undefined4 local_2f;
  undefined4 local_2b;
  undefined2 local_27;
  undefined local_25;
  int local_24;
  int local_20;
  int local_1c;
  int local_18;
  long local_14;
  int *local_10;
  
  local_10 = &argc;
  local_14 = 0;
  local_18 = 1;
  local_2f = 0;
  local_2b = 0;
  local_27 = 0;
  local_25 = 0;
  if (1 < argc) {
    iVar1 = strcmp(argv[1],"I_AM_ROOT");
    if (iVar1 == 0) {
      user_privileges = 99;
      local_18 = local_18 + 1;
    }
    if ((local_18 < argc) && (local_14 = strtol(argv[local_18],(char **)0x0,10), local_14 == 0)) {
      fprintf(stderr,"ERROR: cannot parse port \'%s\'\n",argv[local_18]);
      return 1;
    }
  }
  db_load_from_file();
  local_1c = -1;
  local_20 = -1;
  if (local_14 < 1) {
    recv_fd = 0;
    send_fd = 1;
    fwrite("Server listening successfully on stdin+stdout!\n",1,0x2f,stderr);
  }
  else {
    local_1c = socket(2,1,0);
    if (local_1c < 0) {
      piVar2 = __errno_location();
      fprintf(stderr,"ERROR while creating socket: %d\n",*piVar2);
      return 1;
    }
    local_44.sa_family = 2;
    local_44.sa_data._0_2_ = htons((uint16_t)local_14);
    local_44.sa_data._2_4_ = inet_addr("127.0.0.1");
    iVar1 = bind(local_1c,&local_44,0x10);
    if (iVar1 < 0) {
      piVar2 = __errno_location();
      fprintf(stderr,"ERROR while binding to port %ld: %d\n",local_14,*piVar2);
      return 1;
    }
    iVar1 = listen(local_1c,1);
    if (iVar1 < 0) {
      piVar2 = __errno_location();
      fprintf(stderr,"ERROR while listening on socket: %d\n",*piVar2);
      return 1;
    }
    local_34 = 0x10;
    local_20 = accept(local_1c,&local_54,&local_34);
    if (local_20 < 0) {
      piVar2 = __errno_location();
      fprintf(stderr,"ERROR while accepting connection: %d\n",*piVar2);
      return 1;
    }
    recv_fd = local_20;
    send_fd = local_20;
    fprintf(stderr,"Server listening successfully on %ld!\n",local_14);
  }
  local_24 = process_loop();
  if (-1 < local_1c) {
    close(local_20);
    close(local_1c);
  }
  bVar3 = local_24 < 0;
  if (bVar3) {
    fprintf(stderr,"ERROR: process_loop returned %i!\n",local_24);
  }
  return (uint)bVar3;
}



// WARNING: Function: __x86.get_pc_thunk.bx replaced with injection: get_pc_thunk_bx

void _fini(void)

{
  return;
}



