#ifndef MENU_H
#define MENU_H

#include <stdio.h>

#ifdef _WIN32
   #include <windows.h>

   // Enable VT processing for colors (Windows only)
   #define EnableVTMode() do {                         \
      HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);   \
      if (hOut == INVALID_HANDLE_VALUE) break;         \
      DWORD dwMode = 0;                                \
      if (!GetConsoleMode(hOut, &dwMode)) break;       \
      dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;    \
      SetConsoleMode(hOut, dwMode);                    \
   } while(0)

	// Set console to UTF-8 encoding (Windows only)
   #define Set_UTF8_Encoding() do {                    \
      SetConsoleOutputCP(CP_UTF8);                     \
      SetConsoleCP(CP_UTF8);                           \
   } while(0)

   #define update_screen() do {                        \
      HANDLE handle = GetStdHandle(STD_OUTPUT_HANDLE); \
      COORD coord = { 0, 0 };                          \
      SetConsoleCursorPosition(handle, coord);         \
   } while(0)

   #define clear_screen() system("cls")

#else // Linux / POSIX
   #include <termios.h>
   #include <unistd.h>

   // VT colors and UTF-8 are enabled by default in Linux terminal
   #define EnableVTMode() ((void)0)
   #define Set_UTF8_Encoding() ((void)0)

   #define update_screen() do {                        \
      printf("\033[H");                                \
      fflush(stdout);                                  \
   } while(0)

   #define clear_screen() system("clear")

#endif // _WIN32

typedef enum {
   BUTTON_REG,
   BUTTON_GUEST
} ActiveButtonType;

typedef struct {
   const char *hint;
   const char *btn_reg;
   const char *btn_guest;
   ActiveButtonType type;
} MenuButtons;

// API
void init_menu(MenuButtons *button);
void display_menu(MenuButtons *button);
void handle_menu_selection(MenuButtons *button);

#endif // MENU_H