/* esp32-firmware
 * Copyright (C) 2020-2021 Erik Fleckstein <erik@tinkerforge.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */

#include "esp32_ethernet_brick.h"
#include "module_dependencies.h"

#include <Arduino.h>
#include "driver/i2c.h"

#include "build.h"
#include "tools.h"
#include "hal_arduino_esp32_ethernet_brick/hal_arduino_esp32_ethernet_brick.h"
#include "bindings/errors.h"
#include "event_log.h"
#include "task_scheduler.h"


#if TF_LOCAL_ENABLE != 0

#include "build.h"
#include "bindings/local.h"
// FIXME: for now hardcode DEVICE_IDENTIFIER define here until bindings are ready
//#include "bindings/brick_esp32_ethernet.h"
#define TF_ESP32_ETHERNET_DEVICE_IDENTIFIER 115

#endif

#define GREEN_LED 2
#define BLUE_LED_WARP_ESP32_ETHERNET 2
#define BLUE_LED_ESP32_ETHERNET_BRICK 15
#define BUTTON 0

#define I2C_MASTER_SCL_IO 4
#define I2C_MASTER_SDA_IO 15
#define I2C_MASTER_NUM 0
#define I2C_MASTER_TIMEOUT_MS 1000
#define I2C_TMP1075N_ADDR 0b1001001
#define I2C_RTC_ADDRESS 0b1101000
#define I2C_TMP1075N_TIMEOUT_MS 1000

TF_HAL hal;
extern uint32_t local_uid_num;
extern char local_uid_str[32];
extern char passphrase[20];
extern int8_t blue_led_pin;
extern int8_t green_led_pin;
extern int8_t button_pin;

#if TF_LOCAL_ENABLE != 0

static TF_Local local;

#endif

// Time in seconds.
#ifndef WEM_FACTORY_RESET_WAIT_TIME
#define WEM_FACTORY_RESET_WAIT_TIME 8
#endif

#if defined(BUILD_NAME_ENERGY_MANAGER) && MODULE_FIRMWARE_UPDATE_AVAILABLE()
static void check_for_factory_reset()
{
    logger.printfln("Checking for factory reset for %d seconds", WEM_FACTORY_RESET_WAIT_TIME);

    // A factory reset will leave the green LED on, even across a restart. Switch it off here.
    digitalWrite(green_led_pin, false);

    // Check if ethernet clock seems to be enabled.
    // If it's on, a low pin level can be seen, usually already on the first or second poll.
    bool seen_ethernet_clock = false;
    for (uint32_t i = 0; i < 256; i++) {
        if (!digitalRead(BUTTON)) {
            seen_ethernet_clock = true;
            break;
        }
        // Perturb sampling every 32 cycles for an increasing amount of clock cycles
        // to avoid perfectly syncing up to the ethernet clock by accident.
        if (i % 32 == 31) {
            for (uint32_t j = 0; j < (i/32); j++) {
                __asm("nop.n");
            }
        }
    }

    bool blue_led_off = false;
    if (!seen_ethernet_clock) {
        // Flash LED for 8 seconds while waiting for button press.
        bool button_pressed = false;
        for (uint32_t i = 0; i < (WEM_FACTORY_RESET_WAIT_TIME*10); i++) {
            digitalWrite(blue_led_pin, i % 4 == 0 ? false : true);
            delay(100); // 8 * 10 * 100ms = 8s
            if (!digitalRead(BUTTON)) {
                button_pressed = true;
                break;
            }
        }
        // Blink LED quickly while the button has to stay pressed for almost 8 seconds.
        if (button_pressed) {
            for (uint32_t i = 0; i < 100; i++) {
                digitalWrite(blue_led_pin, i % 2);
                delay(75); // 100 * 75ms = 7.5s
                if (digitalRead(BUTTON)) {
                    button_pressed = false;
                    break;
                }
            }
            // If the button is still pressed, perform factory reset.
            if (button_pressed) {
                // Perform factory reset, switch on blue LED to show success.
                digitalWrite(blue_led_pin, false);
                factory_reset();
            } else {
                // Factory reset aborted, switch off blue LED.
                blue_led_off = true;
            }
        }
    }
    digitalWrite(blue_led_pin, blue_led_off);
}
#endif

void ESP32EthernetBrick::initI2C()
{
    i2c_config_t conf;
    memset(&conf, 0, sizeof(i2c_config_t));
    conf.mode = I2C_MODE_MASTER;
    conf.sda_io_num = I2C_MASTER_SDA_IO;
    conf.scl_io_num = I2C_MASTER_SCL_IO;
    conf.sda_pullup_en = GPIO_PULLUP_ENABLE;
    conf.scl_pullup_en = GPIO_PULLUP_ENABLE;
    conf.master.clk_speed = 100000;

    i2c_param_config(I2C_MASTER_NUM, &conf);
    i2c_driver_install(I2C_MASTER_NUM, conf.mode, 0, 0, 0);
}

bool ESP32EthernetBrick::initHAL()
{
    int result = tf_hal_create(&hal, this->is_warp_esp_ethernet_brick ? 4 : 6);
    if (result != TF_E_OK)
        return false;
    tf_hal_set_timeout(&hal, 100000);
    return true;
}

static uint8_t tmp_cmd_buf[I2C_LINK_RECOMMENDED_SIZE(2)] = {};
static uint8_t tmp_read_buf[2] = {};

void ESP32EthernetBrick::pre_init()
{
    initI2C();

    auto tmp_cmd_handle = i2c_master_prepare_write_read_device(I2C_TMP1075N_ADDR,
                                         tmp_cmd_buf, ARRAY_SIZE(tmp_cmd_buf),
                                         nullptr, 0,
                                         tmp_read_buf, ARRAY_SIZE(tmp_read_buf));
    int ret = i2c_master_cmd_begin(I2C_NUM_0, tmp_cmd_handle, I2C_TMP1075N_TIMEOUT_MS  / portTICK_PERIOD_MS);
    this->is_warp_esp_ethernet_brick = ret == ESP_OK;

    button_pin = BUTTON;

    if (this->is_warp_esp_ethernet_brick) {
        blue_led_pin = BLUE_LED_WARP_ESP32_ETHERNET;
        // green LED is connected directly to 3.3 V
    } else {
        blue_led_pin = BLUE_LED_ESP32_ETHERNET_BRICK;

        green_led_pin = GREEN_LED;
        pinMode(green_led_pin, OUTPUT);
    }

    pinMode(blue_led_pin, OUTPUT);
    pinMode(button_pin, INPUT);
}

void ESP32EthernetBrick::setup()
{
    read_efuses(&local_uid_num, local_uid_str, passphrase);
    logger.printfln("%sESP32 Ethernet Brick UID: %s", this->is_warp_esp_ethernet_brick ? "WARP " : "", local_uid_str);

#if defined(BUILD_NAME_ENERGY_MANAGER) && MODULE_FIRMWARE_UPDATE_AVAILABLE()
    check_for_factory_reset();
#endif

    initHAL();

#if TF_LOCAL_ENABLE != 0
    uint8_t hw_version[3] = {1, 0, 0};
    uint8_t fw_version[3] = {BUILD_VERSION_MAJOR, BUILD_VERSION_MINOR, BUILD_VERSION_PATCH};

    check(tf_local_create(&local, local_uid_str, '0', hw_version, fw_version, TF_ESP32_ETHERNET_DEVICE_IDENTIFIER, &hal), "local create");

    tf_hal_set_local(&hal, &local);
#endif

    task_scheduler.scheduleWithFixedDelay([](){
#if MODULE_WATCHDOG_AVAILABLE()
    static int watchdog_handle = watchdog.add("esp_ethernet_led_blink", "Main thread blocked");
    watchdog.reset(watchdog_handle);
#endif
        led_blink(blue_led_pin, 2000, 1, 0);
    }, 0, 100);

    initialized = true;
}
