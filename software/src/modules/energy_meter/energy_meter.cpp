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

#include "energy_meter.h"

#include "bindings/errors.h"

#include "api.h"
#include "event_log.h"
#include "tools.h"
#include "task_scheduler.h"
#include "modules.h"

extern EventLog logger;

extern TF_HAL hal;
extern TaskScheduler task_scheduler;
extern Config modules;

extern API api;

EnergyMeter::EnergyMeter()
{
    state = Config::Object({
        {"state", Config::Uint8(0)}, // 0 - no energy meter, 1 - initialization error, 2 - meter available
        {"type", Config::Uint8(0)} // 0 - not available, 1 - sdm72, 2 - sdm630, 3 - sdm72v2
    });

    values = Config::Object({
        {"power", Config::Float(0.0)},
        {"energy_rel", Config::Float(0.0)},
        {"energy_abs", Config::Float(0.0)},
    });

    phases = Config::Object({
        {"phases_connected", Config::Array({Config::Bool(false),Config::Bool(false),Config::Bool(false)},
            new Config{Config::Bool(false)},
            3, 3, Config::type_id<Config::ConfBool>())},
        {"phases_active", Config::Array({Config::Bool(false),Config::Bool(false),Config::Bool(false)},
            new Config{Config::Bool(false)},
            3, 3, Config::type_id<Config::ConfBool>())}
    });

    all_values = Config::Array({},
        new Config{Config::Float(0)},
        0, ALL_VALUES_COUNT, Config::type_id<Config::ConfFloat>());

    reset = Config::Null();
}

void EnergyMeter::updateMeterState(uint8_t new_state, uint8_t new_type) {
    state.get("type")->updateUint(new_type);

    if (new_state == 2) {
        this->setupMeter(new_type);
    }
}

void EnergyMeter::updateMeterValues(float power, float energy_rel, float energy_abs)
{
    values.get("power")->updateFloat(power);
    values.get("energy_rel")->updateFloat(energy_rel);
    values.get("energy_abs")->updateFloat(energy_abs);

    power_hist.add_sample(power);
}

void EnergyMeter::updateMeterPhases(bool phases_connected[3], bool phases_active[3])
{
    for (int i = 0; i < 3; ++i)
        phases.get("phases_active")->get(i)->updateBool(phases_active[i]);

    for (int i = 0; i < 3; ++i)
        phases.get("phases_connected")->get(i)->updateBool(phases_connected[i]);
}

void EnergyMeter::updateMeterAllValues(int idx, float val) {
    all_values.get(idx)->updateFloat(val);
}

void EnergyMeter::updateMeterAllValues(float values[ALL_VALUES_COUNT]) {
    for(int i = 0; i < ALL_VALUES_COUNT; ++i)
        all_values.get(i)->updateFloat(values[i]);
}

void EnergyMeter::setupMeter(uint8_t meter_type)
{
    hardware_available = true;

    api.addFeature("meter");
    if (meter_type == 2 || meter_type == 3) {
        api.addFeature("meter_phases");
        api.addFeature("meter_all_values");
    }

    power_hist.setup();

    for (int i = all_values.count(); i < ALL_VALUES_COUNT; ++i) {
        all_values.add();
    }

    initialized = true;
}

void EnergyMeter::setup()
{

}

void EnergyMeter::register_urls()
{
    api.addState("meter/state", &state, {}, 1000);
    api.addState("meter/values", &values, {}, 1000);
    api.addState("meter/phases", &phases, {}, 1000);
    api.addState("meter/all_values", &all_values, {}, 1000);

    power_hist.register_urls("meter/");
}

void EnergyMeter::loop()
{
}
