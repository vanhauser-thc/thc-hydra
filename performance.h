#include <unistd.h>
#include <netdb.h>
#include <errno.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>
#include <fcntl.h>

/* handles select errors */
int my_select(int fd, fd_set * fdread, fd_set * fdwrite, fd_set * fdex, long sec, long usec) {
  int ret_val;
  struct timeval stv;
  fd_set *fdr2, *fdw2, *fde2;

  do {
    fdr2 = fdread;
    fdw2 = fdwrite;
    fde2 = fdex;
    stv.tv_sec = sec;
    stv.tv_usec = usec;
    ret_val = select(fd, fdr2, fdw2, fde2, &stv);
  /* XXX select() sometimes returns errno=EINTR (signal found) */
  } while (ret_val == -1 && errno == EINTR);

  return ret_val;
}

/*reads in a non-blocking way*/
ssize_t read_safe(int fd, void *buffer, size_t len) {
  int r = 0;
  int total = 0;
  int toread = len;
  fd_set fr;
  struct timeval tv;
  int ret = 0;

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
    while ((r = read(fd, (char*) ((char*)buffer + total), toread))) {
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
