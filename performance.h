#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

/* handles select errors */
int32_t my_select(int32_t fd, fd_set *fdread, fd_set *fdwrite, fd_set *fdex, long sec, long usec) {
  int32_t ret_val;
  struct timeval stv;
  fd_set *fdr2, *fdw2, *fde2;

  do {
    fdr2 = fdread;
    fdw2 = fdwrite;
    fde2 = fdex;
    stv.tv_sec = sec;
    stv.tv_usec = usec;
    if (debug > 1)
      printf("before select\n");
    ret_val = select(fd, fdr2, fdw2, fde2, &stv);
    if (debug > 1)
      printf("after select\n");
    /* XXX select() sometimes returns errno=EINTR (signal found) */
  } while (ret_val == -1 && errno == EINTR);

  return ret_val;
}

/*reads in a non-blocking way*/
ssize_t read_safe(int32_t fd, void *buffer, size_t len) {
  int32_t r = 0;
  int32_t total = 0;
  uint32_t toread = len;
  fd_set fr;
  struct timeval tv;
  int32_t ret = 0;

  (void)fcntl(fd, F_SETFL, O_NONBLOCK);
  do {
    FD_ZERO(&fr);
    FD_SET(fd, &fr);
    tv.tv_sec = 0;
    tv.tv_usec = 250000;
    ret = select(fd + 1, &fr, 0, 0, &tv);
    /* XXX select() sometimes return errno=EINTR (signal found) */
  } while (ret == -1 && errno == EINTR);

  if (ret < 0) {
    if (debug) {
      perror("select");
      printf("df:%d\n", fd);
    }
    return -1;
  }

  if (ret > 0) {
    while ((r = read(fd, (char *)((char *)buffer + total), toread))) {
      if (r == -1) {
        if (errno == EAGAIN)
          break;
        return -1;
      }
      total += r;
      toread -= r;
      if (total == len)
        return len;
      if (r == 0)
        return 0;
    }
  }

  return total;
}
