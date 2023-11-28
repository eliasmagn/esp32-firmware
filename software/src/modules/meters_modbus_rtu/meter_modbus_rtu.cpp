/* esp32-firmware
 * Copyright (C) 2023 Erik Fleckstein <erik@tinkerforge.com>
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

#include "meter_modbus_rtu.h"

#include "modules/meters/meter_value_id.h"
#include "modules/meters/sdm_helpers.h"
#include "task_scheduler.h"
#include "tools.h"

//#include "gcc_warnings.h"

#include "sdm630_defs.h"
#include "sdm72dmv2_defs.h"
#include "sdm72dm_defs.h"

static uint16_t write_buf[100];
static uint16_t registers[400];

static MeterInfo *supported_meters[] = {
    &sdm72dm,
    &sdm630,
    &sdm72dmv2
};

_ATTRIBUTE((const))
MeterClassID MeterModbusRTU::get_class() const
{
    return MeterClassID::ModbusRTU;
}

void MeterModbusRTU::cb_read_meter_type(TF_RS485 *rs485, uint8_t request_id, int8_t exception_code, uint16_t *holding_registers, uint16_t holding_registers_length) {
    if (request_id != callback_data.expected_request_id || callback_data.expected_request_id == 0) {
        logger.printfln("Unexpected request id %u, expected %u", request_id, callback_data.expected_request_id);
        callback_data.done = MeterModbusRTU::UserDataDone::ERROR;
        return;
    }

    if (exception_code != 0) {
        if (exception_code != -1)
            logger.printfln("Request %u: Exception code %d", request_id, exception_code);
        callback_data.done = MeterModbusRTU::UserDataDone::ERROR;
        return;
    }

    if (callback_data.value_to_write == nullptr) {
        logger.printfln("value to write was nullptr");
        callback_data.done = MeterModbusRTU::UserDataDone::ERROR;
        return;
    }

    memcpy(callback_data.value_to_write, holding_registers, holding_registers_length * sizeof(uint16_t));

    callback_data.done = MeterModbusRTU::UserDataDone::DONE;

    uint16_t meter_id = *callback_data.value_to_write;

    for (size_t i = 0; i < sizeof(supported_meters) / sizeof(supported_meters[0]); ++i) {
        if (meter_id != supported_meters[i]->meter_id)
            continue;

        this->meter_type = supported_meters[i]->meter_type;
        state->get("type")->updateUint(meter_type);
        this->meter_in_use = supported_meters[i];

        MeterValueID ids[METER_ALL_VALUES_COUNT];
        uint32_t id_count = METER_ALL_VALUES_COUNT;
        sdm_helper_get_value_ids(meter_type, ids, &id_count);
        meters.declare_value_ids(slot, ids, id_count);

        value_index_power      = meters_find_id_index(ids, id_count, MeterValueID::PowerActiveLSumImExDiff);
        value_index_energy_rel = meters_find_id_index(ids, id_count, MeterValueID::EnergyActiveLSumImExSumResettable);
        value_index_energy_abs = meters_find_id_index(ids, id_count, MeterValueID::EnergyActiveLSumImExSum);
        value_index_current_l1 = meters_find_id_index(ids, id_count, MeterValueID::CurrentL1ImExSum);
        value_index_voltage_l1 = meters_find_id_index(ids, id_count, MeterValueID::VoltageL1N);

        logger.printfln("%s detected.", this->meter_in_use->meter_name);
        return;
    }

    logger.printfln("Found unknown meter type 0x%x. Assuming this is a SDM72DM.", meter_id);
    this->meter_type = supported_meters[0]->meter_type;
    state->get("type")->updateUint(meter_type);
    this->meter_in_use = supported_meters[0];

    MeterValueID ids[METER_ALL_VALUES_COUNT];
    uint32_t id_count = METER_ALL_VALUES_COUNT;
    sdm_helper_get_value_ids(meter_type, ids, &id_count);
    meters.declare_value_ids(slot, ids, id_count);

    value_index_power      = meters_find_id_index(ids, id_count, MeterValueID::PowerActiveLSumImExDiff);
    value_index_energy_rel = meters_find_id_index(ids, id_count, MeterValueID::EnergyActiveLSumImExSumResettable);
    value_index_energy_abs = meters_find_id_index(ids, id_count, MeterValueID::EnergyActiveLSumImExSum);
}


void MeterModbusRTU::cb_read_values(TF_RS485 *device, uint8_t request_id, int8_t exception_code, uint16_t *input_registers, uint16_t input_registers_length) {
    if (request_id != callback_data.expected_request_id || callback_data.expected_request_id == 0) {
        logger.printfln("Unexpected request id %u, expected %u", request_id, callback_data.expected_request_id);
        callback_data.done = MeterModbusRTU::UserDataDone::ERROR;
        return;
    }

    if (exception_code != 0) {
        logger.printfln("Request %u: Exception code %d", request_id, exception_code);
        callback_data.done = MeterModbusRTU::UserDataDone::ERROR;
        return;
    }

    if (callback_data.value_to_write == nullptr) {
        logger.printfln("value to write was nullptr");
        callback_data.done = MeterModbusRTU::UserDataDone::ERROR;
        return;
    }

    memcpy(callback_data.value_to_write, input_registers, input_registers_length * sizeof(uint16_t));

    //if (meter.state.get("state")->asUint() == 0 && value.f == 0)
    //    meter.updateMeterState(1);

    //if (meter.state.get("state")->asUint() != 2)
    //    meter.updateMeterState(2);

    callback_data.done = MeterModbusRTU::UserDataDone::DONE;
}

void MeterModbusRTU::cb_write_reset(TF_RS485 *device, uint8_t request_id, int8_t exception_code) {
    if (request_id != callback_data.expected_request_id || callback_data.expected_request_id == 0) {
        logger.printfln("Unexpected request id %u, expected %u", request_id, callback_data.expected_request_id);
        callback_data.done = MeterModbusRTU::UserDataDone::ERROR;
        return;
    }

    // Exclude timeout here:
    // The SDM72DM has a bug in its modbus implementation where it responds to
    // "write multiple registers"-Requests that trigger a reset of the relative energy value
    // with the wrong DeviceID. It sends ID 0 which is reserved for broadcasts
    // and never to be used by slaves!
    // This only happens when writing to 461457, i.e. the reset trigger register.
    //
    // In the future we should check that the reset worked by re-reading the energy value,
    // making sure that it is a small enough value and retrying the reset if not.
    if (exception_code != 0 && exception_code != TF_RS485_EXCEPTION_CODE_TIMEOUT) {
        logger.printfln("Exception code %d", exception_code);
        callback_data.done = MeterModbusRTU::UserDataDone::ERROR;
        return;
    }

    callback_data.done = MeterModbusRTU::UserDataDone::DONE;
}

void MeterModbusRTU::setupMeter() {
    callback_data.expected_request_id = 0;
    callback_data.value_to_write = nullptr;
    callback_data.done = MeterModbusRTU::UserDataDone::DONE;

    // We want to prefill all registers with NaN if two regs are interpreted as float.
    // A NaN is encoded with the exponent filled with ones and the mantissa filled with a non-zero number.
    // Just setting all bits to one works and we don't have to think about the register byte order.
    memset(registers, 0xFF, sizeof(registers));

    uint8_t type_ = config->get("type_override")->asUint();

    if ((type_ - 1) < ARRAY_SIZE(supported_meters)) {
        this->meter_in_use = supported_meters[type_ - 1];
        //meter.updateMeterState(2, this->meter_in_use->meter_type);
        logger.printfln("Meter type override not implemented yet!");
        logger.printfln("Meter type override set to %s.", this->meter_in_use->meter_name);
    } else {
        if (type_ != METER_TYPE_AUTO_DETECT)
            logger.printfln("Meter type override set to unknown value %u. Ignoring", type_);

        callback_data.value_to_write = &this->meter_type;
        tf_rs485_register_modbus_master_read_holding_registers_response_callback(
            rs485,
            [](TF_RS485 *device, uint8_t request_id, int8_t exception_code, uint16_t *regs, uint16_t regs_len, void *user_data){
                auto *m = (MeterModbusRTU *) user_data;
                m->cb_read_meter_type(device, request_id, exception_code, regs, regs_len);
            },
            &meter_type,
            this);

        tf_rs485_modbus_master_read_holding_registers(rs485, 1, 64515, 1, &callback_data.expected_request_id);
    }

    tf_rs485_register_modbus_master_read_input_registers_response_callback(
        rs485,
        [](TF_RS485 *device, uint8_t request_id, int8_t exception_code, uint16_t *regs, uint16_t regs_len, void *user_data){
            auto *m = (MeterModbusRTU *) user_data;
            m->cb_read_values(device, request_id, exception_code, regs, regs_len);
        },
        write_buf,
        this);

    tf_rs485_register_modbus_master_write_multiple_registers_response_callback(
        rs485,
        [](TF_RS485 *device, uint8_t request_id, int8_t exception_code, void *user_data){
            auto *m = (MeterModbusRTU *) user_data;
            m->cb_write_reset(device, request_id, exception_code);
        },
        this);
}

void MeterModbusRTU::setup()
{
    // TODO Trigger meter value update, in case other modules expect meter values during setup.

    if (config->get("type_override")->asUint() == METER_TYPE_NONE) {
        logger.printfln("Meter type override set to NONE (0). Disabling energy meter support.");
        return;
    }

    task_scheduler.scheduleWithFixedDelay([this]() {
        this->tick();
    }, 0, 10);
}

void MeterModbusRTU::register_urls(const String &base_url) {
    // TODO: this is registered automatically?
    //api.addState(base_url + "error_counters", &error_counters, {}, 1000);

    // TODO: How to implement the reset?
    //meter.registerResetCallback([this]() {
        //this->reset_requested = true;
    //});
}


const RegRead *MeterModbusRTU::getNextRead(bool *trigger_fast_read_done, bool *trigger_slow_read_done)
{
    *trigger_fast_read_done = false;
    *trigger_slow_read_done = false;

    if (modbus_read_state_fast != this->meter_in_use->to_read_fast_len) {
        last_read_was_fast = true;
        const RegRead *result = &this->meter_in_use->to_read_fast[modbus_read_state_fast];
        ++modbus_read_state_fast;
        return result;
    }

    // fast state machine is done. do 1 slow read then run the fast state machine again.

    if (last_read_was_fast) {
        *trigger_fast_read_done = true;

        if (modbus_read_state_slow == this->meter_in_use->to_read_slow_len) {
            modbus_read_state_slow = 0;
        }
        if (this->meter_in_use->to_read_slow_len != 0) {
            last_read_was_fast = false;
            const RegRead *result = &this->meter_in_use->to_read_slow[modbus_read_state_slow];
            ++modbus_read_state_slow;
            return result;
        }
    }
    if (modbus_read_state_slow == this->meter_in_use->to_read_slow_len) {
        *trigger_slow_read_done = true;
    }

    modbus_read_state_fast = 0;
    last_read_was_fast = true;
    const RegRead *result = &this->meter_in_use->to_read_fast[modbus_read_state_fast];
    ++modbus_read_state_fast;
    return result;
}

void MeterModbusRTU::tick() {
    if (this->meter_in_use == nullptr)
        return;

    if (callback_data.done == UserDataDone::NOT_DONE && !deadline_elapsed(callback_deadline_ms))
        return;

    if (callback_data.done == UserDataDone::NOT_DONE) {
        logger.printfln("rs485 deadline reached!");
        // TODO
        //meters_modbus_rtu.checkRS485State();
    }

    if (callback_data.done != UserDataDone::NOT_DONE && !deadline_elapsed(next_read_deadline_ms))
        return;

    if (reset_requested) {
        reset_requested = false;

        if (this->meter_in_use->custom_reset_fn != nullptr) {
            this->meter_in_use->custom_reset_fn();
        } else {
            callback_data.done = UserDataDone::NOT_DONE;
            callback_data.value_to_write = nullptr;
            callback_data.expected_request_id = 0;

            uint16_t payload = 0x0003;
            /*TODO is_in_bootloader(*/tf_rs485_modbus_master_write_multiple_registers(rs485, 1, 61457, &payload, 1, &callback_data.expected_request_id)/*)*/;
            if (callback_data.expected_request_id == 0) {
                // TODO
                //meters_modbus_rtu.checkRS485State();
            }
        }
        return;
    }

    bool trigger_fast_read_done;
    bool trigger_slow_read_done;
    const RegRead *next_read = getNextRead(&trigger_fast_read_done, &trigger_slow_read_done);

    auto last_callback_data_done = callback_data.done;

    callback_data.value_to_write = &registers[next_read->start - 1];
    callback_data.done = UserDataDone::NOT_DONE;
    callback_data.expected_request_id = 0;
    /*TODO is_in_bootloader(*/tf_rs485_modbus_master_read_input_registers(rs485, 1, next_read->start, next_read->len, &callback_data.expected_request_id)/*)*/;
    if (callback_data.expected_request_id == 0) {
        logger.printfln("Failed to read energy meter registers starting at %u: request_id: %u", next_read->start, callback_data.expected_request_id);
        // TODO
        //meters_modbus_rtu.checkRS485State();
    }

    if (trigger_fast_read_done) {
        this->meter_in_use->fast_read_done_fn(registers, slot, value_index_power, value_index_energy_rel, value_index_energy_abs, value_index_current_l1, value_index_voltage_l1);
    }

    if (trigger_slow_read_done) {
        this->meter_in_use->slow_read_done_fn(registers, slot);
    }

    if (last_callback_data_done == UserDataDone::DONE) {
        if (trigger_slow_read_done) {
            // Try to measure each 500 ms, but don't pile up measurements
            // if we are already a complete slot behind.
            next_read_deadline_ms = next_read_deadline_ms + 500;
            if (deadline_elapsed(next_read_deadline_ms))
                next_read_deadline_ms = millis() + 500;
        }
    } else if (last_callback_data_done == UserDataDone::ERROR) {
        next_read_deadline_ms = millis() + 500;
        errors->get("meter")->updateUint(errors->get("meter")->asUint() + 1);
    } else {
        next_read_deadline_ms = millis() + 500;
        errors->get("bricklet")->updateUint(errors->get("bricklet")->asUint() + 1);
    }

    // This protects against lost callback responses.
    // If the callback packet is lost,
    // callback_data.done would never be set to ::DONE.
    callback_deadline_ms = millis() + 3000;
}






/*

void MeterModbusRTU::update_from_evse_v2_all_data(EVSEV2::meter_data *meter_data)
{
    // TODO: Add stale data check.
    // Reject stale data older than five seconds.
    //if (deadline_elapsed(all_data.last_update + 5 * 1000))
    //    return;

    // No data to handle if no meter was detected.
    if (meter_data->meter_type == METER_TYPE_NONE)
        return;

    if (meter_type != meter_data->meter_type) {
        if (meter_type != METER_TYPE_NONE) {
            if (!meter_change_warning_printed) {
                logger.printfln("meter_em: Meter change detected. This is not supported.");
                meter_change_warning_printed = true;
            }
            return;
        }

        meter_type = meter_data->meter_type;
        state->get("type")->updateUint(meter_type);

        MeterValueID ids[METER_ALL_VALUES_COUNT];
        uint32_t id_count = METER_ALL_VALUES_COUNT;
        sdm_helper_get_value_ids(meter_type, ids, &id_count);
        meters.declare_value_ids(slot, ids, id_count);

        value_index_power      = meters_find_id_index(ids, id_count, MeterValueID::PowerActiveLSumImExDiff);
        value_index_energy_rel = meters_find_id_index(ids, id_count, MeterValueID::EnergyActiveLSumImExSumResettable);
        value_index_energy_abs = meters_find_id_index(ids, id_count, MeterValueID::EnergyActiveLSumImExSum);

        task_scheduler.scheduleWithFixedDelay([this](){
            update_all_values();
        }, 0, 990);
    }

    meters.update_value(slot, value_index_power, meter_data->power);
    //meters.update_value(slot, value_index_energy_rel, meter_data->energy_relative); // TODO: Add me
    meters.update_value(slot, value_index_energy_abs, meter_data->energy_absolute);

    //TODO API change: replace import/export with phase currents
    //METER_ALL_VALUES_CURRENT_L1_A
    //METER_ALL_VALUES_CURRENT_L2_A
    //METER_ALL_VALUES_CURRENT_L3_A
}

void MeterModbusRTU::update_all_values()
{
    // No need to initialize the array because either all values are written or it is rejected entirely.
    float values[METER_ALL_VALUES_COUNT];
    if (evse_v2.get_all_energy_meter_values(values) != METER_ALL_VALUES_COUNT)
        return;

    uint32_t values_len = ARRAY_SIZE(values);
    sdm_helper_pack_all_values(meter_type, values, &values_len);

    if (values_len == 0) {
        logger.printfln("meter_em: Cannot pack values into array of size %u.", ARRAY_SIZE(values));
    } else {
        meters.update_all_values(slot, values);
    }
}
*/
