#include "menu.h"


// Menu assets
const char hint[] = "\n\n\n\n\tUse \x1B[32mUP\x1B[0m and \x1B[32mDOWN\x1B[0m arrows to navigate, \x1B[32mENTER\x1B[0m to select\n";

const char *logo =
u8"\n\n"
u8"\t\t\x1B[32m████████  ███████ ██                ██   \033[0m\n"
u8"\t\t\x1B[32m██▓      ▓██      ██        ████    ██   \033[0m\n"
u8"\t\t\x1B[32m█▓▓▓░▓   ▓█▓      █▓▓▓██   █▓  ██ ███▓▓██\033[0m\n"
u8"\t\t\x1B[32m▓▓░      ░▓▓      █▓   ▓█  ██▓█▓▓   ▓▓░  \033[0m\n"
u8"\t\t\x1B[32m░▓▓░░▓░░  ░▓░░▓▓░ ▓░   ▓░  ▓░  ▓░    ▓░░ \033[0m\n";

const char *btn_reg =
"\t.----------.\n"
"\t| SIGN IN  |\n"
"\t'----------'\n";

const char *btn_reg_choosed =
"\t\x1B[32m.----------.\033[0m\n"
"\t\x1B[32m| SIGN IN  |\033[0m\n"
"\t\x1B[32m'----------'\033[0m\n";

const char *btn_guest =
"\t.--------------------.\n"
"\t| CONTINUE AS GUEST  |\n"
"\t'--------------------'\n";

const char *btn_guest_choosed =
"\t\x1B[32m.--------------------.\033[0m\n"
"\t\x1B[32m| CONTINUE AS GUEST  |\033[0m\n"
"\t\x1B[32m'--------------------'\033[0m\n";


// API
void init_menu(MenuButtons *button) {
	button->hint = hint;
   button->btn_reg = btn_reg_choosed;
   button->btn_guest = btn_guest;
   button->type = BUTTON_REG;
}

void display_menu(MenuButtons *button) {
   printf("%s", logo);
	printf("%s", button->hint);
   printf("%s", button->btn_reg);
   printf("%s", button->btn_guest);
}

void switch_button(MenuButtons *button) {
   if (button->type == BUTTON_REG) {
      button->type = BUTTON_GUEST;
      button->btn_guest = btn_guest_choosed;
		button->btn_reg = btn_reg;
   } else if (button->type == BUTTON_GUEST) {
		button->type = BUTTON_REG;
      button->btn_reg = btn_reg_choosed;
		button->btn_guest = btn_guest;
   }
}

void reg_pressed(void) {
   printf("REG pressed\n");
}

#define guest_pressed() return;

#ifdef _WIN32

void handle_menu_selection(MenuButtons *button)
{
   HANDLE hInput = GetStdHandle(STD_INPUT_HANDLE);
   INPUT_RECORD record;
   DWORD events;

   // Disable line buffering & echo
   SetConsoleMode(hInput, ENABLE_EXTENDED_FLAGS);

   while (1) {
      ReadConsoleInput(hInput, &record, 1, &events);

      if (record.EventType == KEY_EVENT &&
         record.Event.KeyEvent.bKeyDown) {

         WORD key = record.Event.KeyEvent.wVirtualKeyCode;

         if (key == VK_UP || key == VK_DOWN) {
            switch_button(button);
            update_screen();
            display_menu(button);
         }
         else if (key == VK_RETURN) {
            if (button->type == BUTTON_REG)
               reg_pressed();
            else
               guest_pressed();
         }
      }
   }
}
#else // Linux / POSIX

static void enable_raw_mode(struct termios *orig)
{
   struct termios raw;
   tcgetattr(STDIN_FILENO, orig);
   raw = *orig;

   raw.c_lflag &= ~(ICANON | ECHO);
   raw.c_cc[VMIN] = 1;
   raw.c_cc[VTIME] = 0;

   tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw);
}

static void disable_raw_mode(struct termios *orig)
{
   tcsetattr(STDIN_FILENO, TCSAFLUSH, orig);
}

void handle_menu_selection(MenuButtons *button)
{
   struct termios orig;
   char c;

   enable_raw_mode(&orig);

   while (1) {
      if (read(STDIN_FILENO, &c, 1) != 1)
         continue;

      if (c == '\033') { // ESC
         char seq[2];
         if (read(STDIN_FILENO, &seq[0], 1) != 1) continue;
         if (read(STDIN_FILENO, &seq[1], 1) != 1) continue;

         if (seq[0] == '[' &&
            (seq[1] == 'A' || seq[1] == 'B')) {

            switch_button(button);
            clear_screen();
            display_menu(button);
         }
      }
      else if (c == '\n' || c == '\r') {
         if (button->type == BUTTON_REG)
            reg_pressed();
         else
            guest_pressed();
         break;
      }
   }

   disable_raw_mode(&orig);
}

#endif // _WIN32
