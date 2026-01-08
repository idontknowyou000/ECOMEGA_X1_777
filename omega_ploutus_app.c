// omega_ploutus_app.c
// Flipper Zero Application Example
#include <furi.h>
#include <gui/gui.h>

void omega_ploutus_app(void* p) {
    // Main app logic here
    furi_hal_led_set(FuriHalLedGreen, true); // Example: turn on green LED
    furi_delay_ms(1000);
    furi_hal_led_set(FuriHalLedGreen, false);
}

int32_t omega_ploutus_app_entrypoint(void* p) {
    omega_ploutus_app(p);
    return 0;
}

// Application manifest (application.fam) should reference omega_ploutus_app_entrypoint
