#include <gtk/gtk.h>

int update_statusbar();

void on_quit1_activate(GtkMenuItem * menuitem, gpointer user_data);

void on_about1_activate(GtkMenuItem * menuitem, gpointer user_data);

void on_btnStart_clicked(GtkButton * button, gpointer user_data);

void on_wndMain_destroy(GtkObject * object, gpointer user_data);

void on_btnStop_clicked(GtkButton * button, gpointer user_data);

gboolean on_entTargetFile_button_press_event(GtkWidget * widget, GdkEventButton * event, gpointer user_data);

gboolean on_entUsernameFile_button_press_event(GtkWidget * widget, GdkEventButton * event, gpointer user_data);

gboolean on_entPassFile_button_press_event(GtkWidget * widget, GdkEventButton * event, gpointer user_data);

void on_btnSave_clicked(GtkButton * button, gpointer user_data);

gboolean on_entColonFile_button_press_event(GtkWidget * widget, GdkEventButton * event, gpointer user_data);

void on_chkColon_toggled(GtkToggleButton * togglebutton, gpointer user_data);

void on_btnClear_clicked(GtkButton * button, gpointer user_data);
