
/*
 * This file handles all that needs to be done...
 * Some stuff is stolen from gcombust since I never used pipes... ok, i 
 * only used them in reallife :)
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <gtk/gtk.h>

#include "callbacks.h"
#include "interface.h"
#include "support.h"

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>

int hydra_pid = 0;

char port[10];
char tasks[10];
char timeout[10];
char smbparm[12];
char snmpparm[4];
char sapr3id[4];
char passLoginNull[4];


#define BUF_S 1024

void hydra_select_file(GtkEntry * widget, char *text) {
#ifdef GTK_TYPE_FILE_CHOOSER
  GtkWidget *dialog;
  char *filename;

  dialog = gtk_file_chooser_dialog_new(text, (GtkWindow *) wndMain, GTK_FILE_CHOOSER_ACTION_OPEN,
                                       GTK_STOCK_OPEN, GTK_RESPONSE_ACCEPT, GTK_STOCK_CANCEL, GTK_RESPONSE_CANCEL, NULL);

  if (gtk_dialog_run(GTK_DIALOG(dialog)) == GTK_RESPONSE_ACCEPT) {
    filename = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(dialog));
    gtk_entry_set_text(widget, filename);
    g_free(filename);
  }
  gtk_widget_destroy(dialog);
#endif
}

int hydra_get_options(char *options[]) {
  /* get the stuff from the gtk entries... */
  int i = 1;
  GtkWidget *widget;
  GtkWidget *widget2;
  int j;
  gchar *tmp;
  GString *a;

  options[0] = HYDRA_BIN;

  /* get the port */
  widget = lookup_widget(GTK_WIDGET(wndMain), "spnPort");
  j = gtk_spin_button_get_value_as_int((GtkSpinButton *) widget);
  if (j != 0) {
    snprintf(port, 10, "%d", j);
    options[i++] = "-s";
    options[i++] = port;
  }

  /* prefer ipv6 */
  widget = lookup_widget(GTK_WIDGET(wndMain), "chkIPV6");
  if (gtk_toggle_button_get_active((GtkToggleButton *) widget)) {
    options[i++] = "-6";
  }

  /* use SSL? */
  widget = lookup_widget(GTK_WIDGET(wndMain), "chkSSL");
  if (gtk_toggle_button_get_active((GtkToggleButton *) widget)) {
    options[i++] = "-S";
  }

  /* be verbose? */
  widget = lookup_widget(GTK_WIDGET(wndMain), "chkVerbose");
  if (gtk_toggle_button_get_active((GtkToggleButton *) widget)) {
    options[i++] = "-v";
  }

  /* show attempts */
  widget = lookup_widget(GTK_WIDGET(wndMain), "chkAttempts");
  if (gtk_toggle_button_get_active((GtkToggleButton *) widget)) {
    options[i++] = "-V";
  }

  /* debug mode? */
  widget = lookup_widget(GTK_WIDGET(wndMain), "chkDebug");
  if (gtk_toggle_button_get_active((GtkToggleButton *) widget)) {
    options[i++] = "-d";
  }

  /* use colon separated list? */
  widget = lookup_widget(GTK_WIDGET(wndMain), "chkColon");
  if (gtk_toggle_button_get_active((GtkToggleButton *) widget)) {
    options[i++] = "-C";
    widget = lookup_widget(GTK_WIDGET(wndMain), "entColonFile");
    options[i++] = (char *) gtk_entry_get_text((GtkEntry *) widget);

  } else {
    /* get the username, or username list */
    widget = lookup_widget(GTK_WIDGET(wndMain), "radioUsername1");
    if (gtk_toggle_button_get_active((GtkToggleButton *) widget)) {
      options[i++] = "-l";
      widget = lookup_widget(GTK_WIDGET(wndMain), "entUsername");
      options[i++] = (char *) gtk_entry_get_text((GtkEntry *) widget);
    } else {
      options[i++] = "-L";
      widget = lookup_widget(GTK_WIDGET(wndMain), "entUsernameFile");
      options[i++] = (char *) gtk_entry_get_text((GtkEntry *) widget);
    }

    /* get the pass, or pass list */
    widget = lookup_widget(GTK_WIDGET(wndMain), "radioPass1");
    if (gtk_toggle_button_get_active((GtkToggleButton *) widget)) {
      options[i++] = "-p";
      widget = lookup_widget(GTK_WIDGET(wndMain), "entPass");
      options[i++] = (char *) gtk_entry_get_text((GtkEntry *) widget);
    } else {
      options[i++] = "-P";
      widget = lookup_widget(GTK_WIDGET(wndMain), "entPassFile");
      options[i++] = (char *) gtk_entry_get_text((GtkEntry *) widget);
    }
  }

  /* empty passes / login as pass? */
  memset(passLoginNull, 0, 4);
  widget = lookup_widget(GTK_WIDGET(wndMain), "chkPassNull");
  if (gtk_toggle_button_get_active((GtkToggleButton *) widget)) {
    passLoginNull[0] = 'n';
  }
  widget = lookup_widget(GTK_WIDGET(wndMain), "chkPassLogin");
  if (gtk_toggle_button_get_active((GtkToggleButton *) widget)) {
    if (passLoginNull[0] == 0) {
      passLoginNull[0] = 's';
    } else {
      passLoginNull[1] = 's';
    }
  }
  if (passLoginNull[0] != 0) {
    options[i++] = "-e";
    options[i++] = passLoginNull;
  }

  /* #of tasks */
  widget = lookup_widget(GTK_WIDGET(wndMain), "spnTasks");
  j = gtk_spin_button_get_value_as_int((GtkSpinButton *) widget);
  if (j != 40) {
    snprintf(tasks, 10, "%d", j);
    options[i++] = "-t";
    options[i++] = tasks;
  }

  /* timeout */
  widget = lookup_widget(GTK_WIDGET(wndMain), "spnTimeout");
  j = gtk_spin_button_get_value_as_int((GtkSpinButton *) widget);
  if (j != 30) {
    snprintf(timeout, 10, "%d", j);
    options[i++] = "-w";
    options[i++] = timeout;
  }

  /* loop around users? */
  widget = lookup_widget(GTK_WIDGET(wndMain), "chkUsernameLoop");
  if (gtk_toggle_button_get_active((GtkToggleButton *) widget)) {
    options[i++] = "-u";
  }

  /* exit after first found pair? */
  widget = lookup_widget(GTK_WIDGET(wndMain), "chkExitf");
  if (gtk_toggle_button_get_active((GtkToggleButton *) widget)) {
    options[i++] = "-f";
  }

  /* get additional parameters */
  widget = lookup_widget(GTK_WIDGET(wndMain), "entProtocol");
  tmp = (char *) gtk_entry_get_text((GtkEntry *) widget);

  if (!strncmp(tmp, "http-proxy", 10)) {
    widget = lookup_widget(GTK_WIDGET(wndMain), "entHTTPProxyURL");
    options[i++] = "-m";
    options[i++] = (char *) gtk_entry_get_text((GtkEntry *) widget);

  } else if (!strncmp(tmp, "http-", 5) || !strncmp(tmp, "https-", 6)) {
    options[i++] = "-m";
    widget = lookup_widget(GTK_WIDGET(wndMain), "entHTTPURL");
    options[i++] = (char *) gtk_entry_get_text((GtkEntry *) widget);

  } else if (!strcmp(tmp, "cisco-enable")) {
    options[i++] = "-m";
    widget = lookup_widget(GTK_WIDGET(wndMain), "entCiscoPass");
    options[i++] = (char *) gtk_entry_get_text((GtkEntry *) widget);

  } else if (!strcmp(tmp, "ldap3-crammd5")) {
    options[i++] = "-m";
    widget = lookup_widget(GTK_WIDGET(wndMain), "entLDAPDN");
    options[i++] = (char *) gtk_entry_get_text((GtkEntry *) widget);

  } else if (!strcmp(tmp, "ldap3-digestmd5")) {
    options[i++] = "-m";
    widget = lookup_widget(GTK_WIDGET(wndMain), "entLDAPDN");
    options[i++] = (char *) gtk_entry_get_text((GtkEntry *) widget);

  } else if (!strcmp(tmp, "smb")) {
    memset(smbparm, 0, 12);

    widget = lookup_widget(GTK_WIDGET(wndMain), "chkDomain");
    widget2 = lookup_widget(GTK_WIDGET(wndMain), "chkLocal");
    options[i++] = "-m";
    strncpy(smbparm, "Both", sizeof(smbparm));
    smbparm[strlen("Both")] = '\0';

    if (gtk_toggle_button_get_active((GtkToggleButton *) widget)) {
      strncpy(smbparm, "Domain", sizeof(smbparm));
      smbparm[strlen("Domain")] = '\0';
    }
    if (gtk_toggle_button_get_active((GtkToggleButton *) widget2)) {
      if (gtk_toggle_button_get_active((GtkToggleButton *) widget)) {
        strncpy(smbparm, "Both", sizeof(smbparm));
        smbparm[strlen("Both")] = '\0';
      } else {
        strncpy(smbparm, "Local", sizeof(smbparm));
        smbparm[strlen("Local")] = '\0';
      }
    }
    widget = lookup_widget(GTK_WIDGET(wndMain), "chkNTLM");
    if (gtk_toggle_button_get_active((GtkToggleButton *) widget)) {
        strcat(smbparm, "Hash");
    }
    options[i++] = smbparm;

  } else if (!strcmp(tmp, "sapr3")) {
    widget = lookup_widget(GTK_WIDGET(wndMain), "spnSAPR3");
    j = gtk_spin_button_get_value_as_int((GtkSpinButton *) widget);
    snprintf(sapr3id, sizeof(sapr3id), "%d", j);
    options[i++] = "-m";
    options[i++] = sapr3id;

  } else if (!strcmp(tmp, "cvs") || !strcmp(tmp, "svn")) {
    widget = lookup_widget(GTK_WIDGET(wndMain), "entCVS");
    options[i++] = "-m";
    options[i++] = (char *) gtk_entry_get_text((GtkEntry *) widget);

  } else if (!strcmp(tmp, "snmp")) {
    memset(snmpparm, 0, 4);
    widget = lookup_widget(GTK_WIDGET(wndMain), "radioSNMPVer1");
    if (gtk_toggle_button_get_active((GtkToggleButton *) widget)) {
      snmpparm[0] = '1';
    } else {
      snmpparm[0] = '2';
    }

    widget = lookup_widget(GTK_WIDGET(wndMain), "radioSNMPWrite");
    if (gtk_toggle_button_get_active((GtkToggleButton *) widget)) {
      snmpparm[0] = 'w';
    } else {
      snmpparm[0] = 'r';
    }

    options[i++] = "-m";
    options[i++] = snmpparm;
  } else if (!strcmp(tmp, "telnet")) {
    widget = lookup_widget(GTK_WIDGET(wndMain), "entTelnet");
    if ((char *) gtk_entry_get_text((GtkEntry *) widget) != NULL) {
      options[i++] = "-m";
      options[i++] = (char *) gtk_entry_get_text((GtkEntry *) widget);
    }
  }

  /* clean up proxy settings */
  unsetenv("HYDRA_PROXY_HTTP");
  unsetenv("HYDRA_PROXY_CONNECT");
  unsetenv("HYDRA_PROXY_AUTH");

  /* proxy support */
  widget = lookup_widget(GTK_WIDGET(wndMain), "radioProxy");

  if (!gtk_toggle_button_get_active((GtkToggleButton *) widget)) {

    widget2 = lookup_widget(GTK_WIDGET(wndMain), "entHTTPProxy");
    widget = lookup_widget(GTK_WIDGET(wndMain), "radioProxy2");

    /* which variable do we set? */
    if ((!strncmp(tmp, "http-", 5)) && (gtk_toggle_button_get_active((GtkToggleButton *) widget))) {
      setenv("HYDRA_PROXY_HTTP", gtk_entry_get_text((GtkEntry *) widget2), 1);
    } else {
      setenv("HYDRA_PROXY_CONNECT", (char *) gtk_entry_get_text((GtkEntry *) widget2), 1);
    }

    /* do we need to provide user and pass? */
    widget = lookup_widget(GTK_WIDGET(wndMain), "chkProxyAuth");
    if (gtk_toggle_button_get_active((GtkToggleButton *) widget)) {
      widget = lookup_widget(GTK_WIDGET(wndMain), "entProxyUser");
      widget2 = lookup_widget(GTK_WIDGET(wndMain), "entProxyPass");
      a = g_string_new((gchar *) gtk_entry_get_text((GtkEntry *) widget));
      a = g_string_append_c(a, ':');
      a = g_string_append(a, gtk_entry_get_text((GtkEntry *) widget2));
      setenv("HYDRA_PROXY_AUTH", a->str, 1);
      (void) g_string_free(a, TRUE);
    }
  }

  /* get the target, or target list */
  widget = lookup_widget(GTK_WIDGET(wndMain), "radioTarget1");
  if (gtk_toggle_button_get_active((GtkToggleButton *) widget)) {
    widget = lookup_widget(GTK_WIDGET(wndMain), "entTarget");
    options[i++] = (char *) gtk_entry_get_text((GtkEntry *) widget);
  } else {
    options[i++] = "-M";
    widget = lookup_widget(GTK_WIDGET(wndMain), "entTargetFile");
    options[i++] = (char *) gtk_entry_get_text((GtkEntry *) widget);
  }

  /* get the service */
  widget = lookup_widget(GTK_WIDGET(wndMain), "entProtocol");
  options[i++] = (char *) gtk_entry_get_text((GtkEntry *) widget);

  options[i] = NULL;
  return i;
}

int update_statusbar() {
  int i, j;
  char *options[128];
  guint context_id;
  GtkStatusbar *statusbar;
  extern guint message_id;
  GString *statustext = g_string_new("hydra ");

  i = hydra_get_options(options);

  for (j = 1; j < i; j++) {

    statustext = g_string_append(statustext, options[j]);
    statustext = g_string_append_c(statustext, ' ');
  }

  statusbar = (GtkStatusbar *) lookup_widget(GTK_WIDGET(wndMain), "statusbar");
  context_id = gtk_statusbar_get_context_id(statusbar, "status");

  /* an old message in stack? */
  if (message_id != 0) {
    gtk_statusbar_remove(statusbar, context_id, message_id);
  }

  message_id = gtk_statusbar_push(statusbar, context_id, (gchar *) statustext->str);

  (void) g_string_free(statustext, TRUE);

  return TRUE;
}

int read_into(int fd) {
  char in_buf[BUF_S];
  char *passline;
  char *start, *end;
  int result;
  GtkWidget *output;
  GtkTextBuffer *outputbuf;
  GtkTextIter outputiter;

  if ((result = read(fd, in_buf, BUF_S - 1)) < 0) {
    g_warning("%s::%i: read returned negative!", __FILE__, __LINE__);
    return FALSE;
  } else if (result == 0) {
    return FALSE;
  } else {
    in_buf[result] = 0;
  }

  output = lookup_widget(GTK_WIDGET(wndMain), "txtOutput");
  outputbuf = gtk_text_view_get_buffer((GtkTextView *) output);

  gtk_text_buffer_get_iter_at_offset(outputbuf, &outputiter, -1);


  if ((passline = strstr(in_buf, "password: ")) == NULL) {
    gtk_text_buffer_insert(outputbuf, &outputiter, in_buf, result);
  } else {
    start = in_buf;
    end = in_buf;
    while ((end = (strchr(end + 1, '\n'))) < passline) {
      start = end;
    }

    if (start != in_buf) {
      gtk_text_buffer_insert(outputbuf, &outputiter, in_buf, (start - in_buf + 1));
    }
    gtk_text_buffer_insert_with_tags_by_name(outputbuf, &outputiter, start, (end - start + 1), "bold", NULL);

    if (end - in_buf - result > 0) {
      gtk_text_buffer_insert(outputbuf, &outputiter, end + 1, -1);
    }

  }


  if (strstr(in_buf, " finished at ") != NULL) {
    gtk_text_buffer_insert_with_tags_by_name(outputbuf, &outputiter, "<finished>\n\n", -1, "bold", NULL);
  }

  if (result == BUF_S - 1)      /* there might be more available, recurse baby! */
    return read_into(fd);
  else
    return TRUE;
}

/* wait for hydra output */

static int wait_hydra_output(gpointer data) {
  static int stdout_ok = TRUE, stderr_ok = TRUE;
  fd_set rset;
  struct timeval tv;
  int result, max;
  int *fd = data;
  int status;

  g_assert((stdout_ok == TRUE) || (stderr_ok == TRUE));

  tv.tv_sec = 0;
  tv.tv_usec = 0;

  FD_ZERO(&rset);
  max = -1;

  if (stdout_ok) {
    FD_SET(fd[0], &rset);
    max = fd[0];
  }
  if (stderr_ok) {
    FD_SET(fd[1], &rset);
    if (-1 == max)
      max = fd[1];
    else
      max = fd[0] > fd[1] ? fd[0] : fd[1];
  }

  result = select(max + 1, &rset, NULL, NULL, &tv);

  if (result < 0)
    g_error("wait_hydra_output: select returned negative!");
  else if (result == 0)
    return TRUE;

  if (stdout_ok && FD_ISSET(fd[0], &rset))
    stdout_ok = read_into(fd[0]);
  if (stderr_ok && FD_ISSET(fd[1], &rset))
    stderr_ok = read_into(fd[1]);

  if (!(stdout_ok || stderr_ok)) {
    waitpid(hydra_pid, &status, 0);
    hydra_pid = 0;
    stdout_ok = stderr_ok = TRUE;
    return FALSE;
  } else
    return TRUE;
}


/* assumes a successfull pipe() won't set the fd's to -1 */
static void close_pipe(int *pipe) {
  if (-1 != pipe[0]) {
    close(pipe[0]);
    pipe[0] = -1;
  }
  if (-1 != pipe[1]) {
    close(pipe[1]);
    pipe[1] = -1;
  }
}

/* executes the command stored in command->elemets (which is suitable for execv())
 * returns an int *pfd with file descriptors:
 * pfd[0] STDOUT output of the command and
 * pfd[1] STDERR output of the command
 */

int *popen_re_unbuffered(char *command) {
  static int p_r[2] = { -1, -1 }, p_e[2] = {
  -1, -1};
  static int *pfd = NULL;

  char *options[128];
  hydra_pid = 0;

  update_statusbar();

  /* only allocate once */
  if (NULL == pfd)
    pfd = malloc(sizeof(int) * 2);

  /* clean up from last command */
  close_pipe(p_r);
  close_pipe(p_e);

  if (pipe(p_r) < 0 || pipe(p_e) < 0) {
    g_warning("popen_rw_unbuffered: Error creating pipe!");
    return NULL;
  }

  if ((hydra_pid = fork()) < 0) {
    g_warning("popen_rw_unbuffered: Error forking!");
    return NULL;
  } else if (hydra_pid == 0) {  /* child */
    int k;
    if (setpgid(getpid(), getpid()) < 0)
      g_warning("popen_rw_unbuffered: setpgid() failed");
    if (close(p_r[0]) < 0)
      g_warning("popen_rw_unbuffered: close(p_r[0]) failed");
    if (p_r[1] != STDOUT_FILENO)
      if (dup2(p_r[1], STDOUT_FILENO) < 0)
        g_warning("popen_rw_unbuffered: child dup2 STDOUT failed!");
    if (close(p_r[1]) < 0)
      g_warning("popen_rw_unbuffered: close(p_r[1]) failed");

    if (close(p_e[0]) < 0)
      g_warning("popen_rw_unbuffered: close(p_e[0]) failed");
    if (p_e[1] != STDERR_FILENO)
      if (dup2(p_e[1], STDERR_FILENO) < 0)
        g_warning("popen_rw_unbuffered: child dup2 STDERR failed!");
    if (close(p_e[1]) < 0)
      g_warning("popen_rw_unbuffered: close(p_e[1]) failed");

    (void) hydra_get_options(options);

    execv(HYDRA_BIN, options);

    g_warning("%s %i: popen_rw_unbuffered: execv() returned", __FILE__, __LINE__);
    
    for (k = 0; options[k] != NULL; k++) {
      g_warning("%s", options[k]);
    }
    gtk_main_quit();
  } else {                      /* parent */
    if (close(p_r[1]) < 0)
      g_warning("popen_rw_unbuffered: close(p_r[1]) (parent) failed");
    if (close(p_e[1]) < 0)
      g_warning("popen_rw_unbuffered: close(p_e[1]) (parent) failed");
    pfd[0] = p_r[0];
    pfd[1] = p_e[0];
    return pfd;
  }
  g_assert_not_reached();
  return pfd;
}

void on_quit1_activate(GtkMenuItem * menuitem, gpointer user_data) {
  gtk_main_quit();
}


void on_about1_activate(GtkMenuItem * menuitem, gpointer user_data) {

}

void on_btnStart_clicked(GtkButton * button, gpointer user_data) {
  int *fd = NULL;

  fd = popen_re_unbuffered(NULL);
  g_timeout_add(200, wait_hydra_output, fd);

}

void on_btnStop_clicked(GtkButton * button, gpointer user_data) {
  if (hydra_pid != 0) {
    kill(hydra_pid, SIGTERM);
    hydra_pid = 0;
  }
}


void on_wndMain_destroy(GtkObject * object, gpointer user_data) {
  if (hydra_pid != 0) {
    kill(hydra_pid, SIGTERM);
    hydra_pid = 0;
  }
  gtk_main_quit();
}



gboolean on_entTargetFile_button_press_event(GtkWidget * widget, GdkEventButton * event, gpointer user_data) {
  hydra_select_file((GtkEntry *) widget, "Select target list");
  gtk_widget_grab_focus(widget);
  return TRUE;
}


gboolean on_entUsernameFile_button_press_event(GtkWidget * widget, GdkEventButton * event, gpointer user_data) {
  hydra_select_file((GtkEntry *) widget, "Select username list");
  gtk_widget_grab_focus(widget);
  return TRUE;
}


gboolean on_entPassFile_button_press_event(GtkWidget * widget, GdkEventButton * event, gpointer user_data) {
  hydra_select_file((GtkEntry *) widget, "Select password list");
  gtk_widget_grab_focus(widget);
  return TRUE;
}

gboolean on_entColonFile_button_press_event(GtkWidget * widget, GdkEventButton * event, gpointer user_data) {
  hydra_select_file((GtkEntry *) widget, "Select colon separated user,password list");
  gtk_widget_grab_focus(widget);
  return TRUE;
}

void on_btnSave_clicked(GtkButton * button, gpointer user_data) {
#ifdef GTK_TYPE_FILE_CHOOSER
  GtkWidget *dialog;
  char *filename;
  gchar *text;
  int fd;
  GtkWidget *output;
  GtkTextBuffer *outputbuf;
  GtkTextIter start;
  GtkTextIter end;

  dialog = gtk_file_chooser_dialog_new("Save output", (GtkWindow *) wndMain, GTK_FILE_CHOOSER_ACTION_SAVE,
                                       GTK_STOCK_SAVE, GTK_RESPONSE_ACCEPT, GTK_STOCK_CANCEL, GTK_RESPONSE_CANCEL, NULL);
  if (gtk_dialog_run(GTK_DIALOG(dialog)) == GTK_RESPONSE_ACCEPT) {
    filename = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(dialog));

    output = lookup_widget(GTK_WIDGET(wndMain), "txtOutput");
    outputbuf = gtk_text_view_get_buffer((GtkTextView *) output);
    gtk_text_buffer_get_start_iter(outputbuf, &start);
    gtk_text_buffer_get_end_iter(outputbuf, &end);

    text = gtk_text_buffer_get_text(outputbuf, &start, &end, TRUE);

    fd = open(filename, O_CREAT | O_TRUNC | O_WRONLY, 0644);
    if (fd > 0) {
      write(fd, text, strlen(text));
      close(fd);
    }
    g_free(text);
    g_free(filename);
  }
  gtk_widget_destroy(dialog);
#endif
}

void on_chkColon_toggled(GtkToggleButton * togglebutton, gpointer user_data) {
  GtkWidget *user, *pass;
  user = lookup_widget(GTK_WIDGET(wndMain), "frmUsername");;
  pass = lookup_widget(GTK_WIDGET(wndMain), "frmPass");

  if (gtk_toggle_button_get_active(togglebutton)) {
    gtk_widget_set_sensitive(user, FALSE);
    gtk_widget_set_sensitive(pass, FALSE);
  } else {
    gtk_widget_set_sensitive(user, TRUE);
    gtk_widget_set_sensitive(pass, TRUE);
  }
}

void on_btnClear_clicked(GtkButton * button, gpointer user_data) {
  GtkWidget *output;
  GtkTextBuffer *outputbuf;

  output = lookup_widget(GTK_WIDGET(wndMain), "txtOutput");
  outputbuf = gtk_text_view_get_buffer((GtkTextView *) output);
  gtk_text_buffer_set_text(outputbuf, "", -1);
}
