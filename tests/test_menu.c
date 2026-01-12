#include "menu.h"

int main(void) {
	EnableVTMode();
	Set_UTF8_Encoding();

	MenuButtons menu_button;

	init_menu(&menu_button);
	display_menu(&menu_button);
	handle_menu_selection(&menu_button);

	clear_screen();
	printf("You exited menu\n");

	return 0;
}