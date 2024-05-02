/* esp32-firmware
 * Copyright (C) 2023 Mattias Schäffersmann <mattias@tinkerforge.com>
 * Copyright (C) 2024 Matthias Bolte <matthias@tinkerforge.com>
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

#define EVENT_LOG_PREFIX "meters_mbtcp"

#include "meter_modbus_tcp.h"
#include "modbus_tcp_tools.h"
#include "module_dependencies.h"

#include "event_log.h"
#include "task_scheduler.h"

#include "gcc_warnings.h"

#include "meters_modbus_tcp_defs.inc"

//#define DEBUG_LOG_ALL_VALUES

#define SUNGROW_INVERTER_OUTPUT_TYPE_ADDRESS            5002u
#define SUNGROW_INVERTER_MPPT_1_VOLTAGE_ADDRESS         5011u
#define SUNGROW_INVERTER_MPPT_1_CURRENT_ADDRESS         5012u
#define SUNGROW_INVERTER_MPPT_2_VOLTAGE_ADDRESS         5013u
#define SUNGROW_INVERTER_MPPT_2_CURRENT_ADDRESS         5014u
#define SUNGROW_INVERTER_GRID_FREQUENCY_ADDRESS         5036u
#define SUNGROW_HYBRID_INVERTER_RUNNING_STATE_ADDRESS   13001u
#define SUNGROW_HYBRID_INVERTER_BATTERY_CURRENT_ADDRESS 13021u
#define SUNGROW_HYBRID_INVERTER_BATTERY_POWER_ADDRESS   13022u

MeterClassID MeterModbusTCP::get_class() const
{
    return MeterClassID::ModbusTCP;
}

void MeterModbusTCP::setup(const Config &ephemeral_config)
{
    host_name      = ephemeral_config.get("host")->asString();
    port           = static_cast<uint16_t>(ephemeral_config.get("port")->asUint());
    device_address = static_cast<uint8_t>(ephemeral_config.get("device_address")->asUint());
    table_id       = ephemeral_config.get("table")->getTag<MeterModbusTCPTableID>();

    switch (table_id) {
    case MeterModbusTCPTableID::None:
        logger.printfln("No table selected");
        return;

    //case MeterModbusTCPTableID::Custom:

    case MeterModbusTCPTableID::SungrowHybridInverter:
        generic_read_request.register_type = TAddress::RegType::IREG;
        generic_read_request.start_address_offset = 1; // register number mode
        sungrow_hybrid_inverter_virtual_meter = ephemeral_config.get("table")->get()->get("virtual_meter")->asEnum<SungrowHybridInverterVirtualMeterID>();

        switch (sungrow_hybrid_inverter_virtual_meter) {
        case SungrowHybridInverterVirtualMeterID::None:
            logger.printfln("No Sungrow Hybrid Inverter Virtual Meter selected");
            return;

        case SungrowHybridInverterVirtualMeterID::Inverter:
            // will be set after output type discovery
            table = nullptr;
            break;

        case SungrowHybridInverterVirtualMeterID::Grid:
            table = &sungrow_hybrid_inverter_grid_table;
            break;

        case SungrowHybridInverterVirtualMeterID::Battery:
            table = &sungrow_hybrid_inverter_battery_table;
            break;

        case SungrowHybridInverterVirtualMeterID::Load:
            table = &sungrow_hybrid_inverter_load_table;
            break;

        default:
            logger.printfln("Unknown Sungrow Hybrid Inverter Virtual Meter: %u", static_cast<uint8_t>(sungrow_hybrid_inverter_virtual_meter));
            return;
        }

        break;

    case MeterModbusTCPTableID::SungrowStringInverter:
        generic_read_request.register_type = TAddress::RegType::IREG;
        generic_read_request.start_address_offset = 1; // register number mode
        sungrow_string_inverter_virtual_meter = ephemeral_config.get("table")->get()->get("virtual_meter")->asEnum<SungrowStringInverterVirtualMeterID>();

        switch (sungrow_string_inverter_virtual_meter) {
        case SungrowStringInverterVirtualMeterID::None:
            logger.printfln("No Sungrow String Inverter Virtual Meter selected");
            return;

        case SungrowStringInverterVirtualMeterID::Inverter:
            // will be set after output type discovery
            table = nullptr;
            break;

        case SungrowStringInverterVirtualMeterID::Grid:
            table = &sungrow_string_inverter_grid_table;
            break;

        case SungrowStringInverterVirtualMeterID::Load:
            table = &sungrow_string_inverter_load_table;
            break;

        default:
            logger.printfln("Unknown Sungrow String Inverter Virtual Meter: %u", static_cast<uint8_t>(sungrow_string_inverter_virtual_meter));
            return;
        }

        break;

    case MeterModbusTCPTableID::SolarmaxMaxStorage:
        generic_read_request.register_type = TAddress::RegType::IREG;
        generic_read_request.start_address_offset = 0; // register address mode
        solarmax_max_storage_virtual_meter = ephemeral_config.get("table")->get()->get("virtual_meter")->asEnum<SolarmaxMaxStorageVirtualMeterID>();

        switch (solarmax_max_storage_virtual_meter) {
        case SolarmaxMaxStorageVirtualMeterID::None:
            logger.printfln("No Solarmax Max Storage Virtual Meter selected");
            return;

        case SolarmaxMaxStorageVirtualMeterID::Inverter:
            table = &solarmax_max_storage_inverter_table;
            break;

        case SolarmaxMaxStorageVirtualMeterID::Grid:
            table = &solarmax_max_storage_grid_table;
            break;

        case SolarmaxMaxStorageVirtualMeterID::Battery:
            table = &solarmax_max_storage_battery_table;
            break;

        default:
            logger.printfln("Unknown Solarmax Max Storage Virtual Meter: %u", static_cast<uint8_t>(solarmax_max_storage_virtual_meter));
            return;
        }

        break;

    default:
        logger.printfln("Unknown table: %u", static_cast<uint8_t>(table_id));
        return;
    }

    if (table != nullptr) {
        meters.declare_value_ids(slot, table->ids, table->ids_length);
    }

    task_scheduler.scheduleOnce([this]() {
        this->read_allowed = false;
        this->start_connection();
    }, 1000);

    task_scheduler.scheduleWithFixedDelay([this]() {
        if (this->read_allowed) {
            this->read_allowed = false;
            this->start_generic_read();
        };
    }, 2000, 1000);
}

void MeterModbusTCP::connect_callback()
{
    generic_read_request.data[0] = register_buffer;
    generic_read_request.data[1] = nullptr;
    generic_read_request.read_twice = false;
    generic_read_request.done_callback = [this]{ read_done_callback(); };

    if (is_sungrow_inverter_meter()) {
        if (sungrow_inverter_output_type < 0) {
            generic_read_request.start_address = SUNGROW_INVERTER_OUTPUT_TYPE_ADDRESS; // read output type
            generic_read_request.register_count = 1;
        }
    }
    else {
        read_index = 0;

        prepare_read();
    }

    start_generic_read();
}

void MeterModbusTCP::disconnect_callback()
{
    read_allowed = false;
}

void MeterModbusTCP::prepare_read()
{
    while (
#ifndef DEBUG_LOG_ALL_VALUES
        table->index[read_index] == VALUE_INDEX_DEBUG ||
#endif
        table->specs[read_index].start_address == START_ADDRESS_VIRTUAL) {
        read_index = (read_index + 1) % table->specs_length;
    }

    generic_read_request.start_address = table->specs[read_index].start_address;
    generic_read_request.register_count = static_cast<uint8_t>(table->specs[read_index].value_type) % 10;
}

bool MeterModbusTCP::is_sungrow_inverter_meter() const
{
    return (table_id == MeterModbusTCPTableID::SungrowHybridInverter
         && sungrow_hybrid_inverter_virtual_meter == SungrowHybridInverterVirtualMeterID::Inverter)
        || (table_id == MeterModbusTCPTableID::SungrowStringInverter
         && sungrow_string_inverter_virtual_meter == SungrowStringInverterVirtualMeterID::Inverter);
}

bool MeterModbusTCP::is_sungrow_grid_meter() const
{
    return (table_id == MeterModbusTCPTableID::SungrowHybridInverter
         && sungrow_hybrid_inverter_virtual_meter == SungrowHybridInverterVirtualMeterID::Grid)
        || (table_id == MeterModbusTCPTableID::SungrowStringInverter
         && sungrow_string_inverter_virtual_meter == SungrowStringInverterVirtualMeterID::Grid);
}

bool MeterModbusTCP::is_sungrow_battery_meter() const
{
    return table_id == MeterModbusTCPTableID::SungrowHybridInverter
        && sungrow_hybrid_inverter_virtual_meter == SungrowHybridInverterVirtualMeterID::Battery;
}

void MeterModbusTCP::read_done_callback()
{
    if (generic_read_request.result_code != Modbus::ResultCode::EX_SUCCESS) {
        read_allowed = true;

        if (is_sungrow_inverter_meter()
         && generic_read_request.start_address == SUNGROW_INVERTER_OUTPUT_TYPE_ADDRESS) {
            logger.printfln("Error reading %s / Output Type (%u): %s [%d]",
                            get_table_name(table_id),
                            SUNGROW_INVERTER_OUTPUT_TYPE_ADDRESS,
                            get_modbus_result_code_name(generic_read_request.result_code),
                            generic_read_request.result_code);
        }
        else {
            logger.printfln("Error reading %s / %s (%zu): %s [%d]",
                            get_table_name(table_id),
                            table->specs[read_index].name,
                            table->specs[read_index].start_address,
                            get_modbus_result_code_name(generic_read_request.result_code),
                            generic_read_request.result_code);
        }

        return;
    }

    if (is_sungrow_inverter_meter()
     && generic_read_request.start_address == SUNGROW_INVERTER_OUTPUT_TYPE_ADDRESS) {
        if (sungrow_inverter_output_type < 0) {
            switch (register_buffer[0]) {
            case 0:
                if (table_id == MeterModbusTCPTableID::SungrowHybridInverter) {
                    table = &sungrow_hybrid_inverter_1p2l_table;
                }
                else { // MeterModbusTCPTableID::SungrowStringInverter
                    table = &sungrow_string_inverter_1p2l_table;
                }

                break;

            case 1:
                if (table_id == MeterModbusTCPTableID::SungrowHybridInverter) {
                    table = &sungrow_hybrid_inverter_3p4l_table;
                }
                else { // MeterModbusTCPTableID::SungrowStringInverter
                    table = &sungrow_string_inverter_3p4l_table;
                }

                break;

            case 2:
                if (table_id == MeterModbusTCPTableID::SungrowHybridInverter) {
                    table = &sungrow_hybrid_inverter_3p3l_table;
                }
                else { // MeterModbusTCPTableID::SungrowStringInverter
                    table = &sungrow_string_inverter_3p3l_table;
                }

                break;

            default:
                logger.printfln("%s has unknown Output Type: %u", get_table_name(table_id), register_buffer[0]);
                return;
            }

            sungrow_inverter_output_type = register_buffer[0];

#ifdef DEBUG_LOG_ALL_VALUES
            logger.printfln("%s / Output Type (%u): %d",
                            get_table_name(table_id),
                            SUNGROW_INVERTER_OUTPUT_TYPE_ADDRESS,
                            sungrow_inverter_output_type);
#endif

            meters.declare_value_ids(slot, table->ids, table->ids_length);
        }

        read_allowed = true;
        read_index = 0;

        prepare_read();

        return;
    }

    union {
        uint32_t v;
        uint16_t r[2];
    } u;

    u.r[0] = register_buffer[0];
    u.r[1] = register_buffer[1];

    float value = NAN;

    switch (table->specs[read_index].value_type) {
    case ValueType::U16:
#ifdef DEBUG_LOG_ALL_VALUES
        logger.printfln("%s / %s (%zu): %u",
                        get_table_name(table_id),
                        table->specs[read_index].name,
                        table->specs[read_index].start_address,
                        register_buffer[0]);
#endif

        value = static_cast<float>(register_buffer[0]);
        break;

    case ValueType::S16:
#ifdef DEBUG_LOG_ALL_VALUES
        logger.printfln("%s / %s (%zu): %d",
                        get_table_name(table_id),
                        table->specs[read_index].name,
                        table->specs[read_index].start_address,
                        static_cast<int16_t>(register_buffer[0]));
#endif

        value = static_cast<float>(static_cast<int16_t>(register_buffer[0]));
        break;

    case ValueType::U32:
#ifdef DEBUG_LOG_ALL_VALUES
        logger.printfln("%s / %s (%zu): %u (%u %u)",
                        get_table_name(table_id),
                        table->specs[read_index].name,
                        table->specs[read_index].start_address,
                        u.v,
                        register_buffer[0],
                        register_buffer[1]);
#endif

        value = static_cast<float>(u.v);
        break;

    case ValueType::S32:
#ifdef DEBUG_LOG_ALL_VALUES
        logger.printfln("%s / %s (%zu): %d (%u %u)",
                        get_table_name(table_id),
                        table->specs[read_index].name,
                        table->specs[read_index].start_address,
                        static_cast<int32_t>(u.v),
                        register_buffer[0],
                        register_buffer[1]);
#endif

        value = static_cast<float>(static_cast<int32_t>(u.v));
        break;

    default:
        break;
    }

    value *= table->specs[read_index].scale_factor;

    if (is_sungrow_inverter_meter()) {
        if (generic_read_request.start_address == SUNGROW_INVERTER_MPPT_1_VOLTAGE_ADDRESS) {
            sungrow_inverter_mppt_1_voltage = value;
        }
        else if (generic_read_request.start_address == SUNGROW_INVERTER_MPPT_1_CURRENT_ADDRESS) {
            sungrow_inverter_mppt_1_current = value;
        }
        else if (generic_read_request.start_address == SUNGROW_INVERTER_MPPT_2_VOLTAGE_ADDRESS) {
            sungrow_inverter_mppt_2_voltage = value;
        }
        else if (generic_read_request.start_address == SUNGROW_INVERTER_MPPT_2_CURRENT_ADDRESS) {
            sungrow_inverter_mppt_2_current = value;

            float current = sungrow_inverter_mppt_1_current + sungrow_inverter_mppt_2_current;
            float voltage;

            if (current > 0.0f) {
                voltage = (sungrow_inverter_mppt_1_voltage * sungrow_inverter_mppt_1_current) / current
                        + (sungrow_inverter_mppt_2_voltage * sungrow_inverter_mppt_2_current) / current;
            }
            else {
                voltage = (sungrow_inverter_mppt_1_voltage + sungrow_inverter_mppt_2_voltage) / 2.0f;
            }

            meters.update_value(slot, table->index[read_index + 1], voltage);
            meters.update_value(slot, table->index[read_index + 2], current);
        }
    }
    else if (is_sungrow_grid_meter()) {
        if (generic_read_request.start_address == SUNGROW_INVERTER_GRID_FREQUENCY_ADDRESS) {
            if (value > 100) {
                // according to the spec the grid frequency is given
                // as 0.1 Hz, but some inverters report it as 0.01 Hz
                value /= 10;
            }
        }
    }
    else if (is_sungrow_battery_meter()) {
        if (generic_read_request.start_address == SUNGROW_HYBRID_INVERTER_RUNNING_STATE_ADDRESS) {
            sungrow_hybrid_inverter_running_state = register_buffer[0];
        }
        else if (generic_read_request.start_address == SUNGROW_HYBRID_INVERTER_BATTERY_CURRENT_ADDRESS) {
            if ((sungrow_hybrid_inverter_running_state & (1 << 2)) != 0) {
                value = -value;
            }
        }
        else if (generic_read_request.start_address == SUNGROW_HYBRID_INVERTER_BATTERY_POWER_ADDRESS) {
            if ((sungrow_hybrid_inverter_running_state & (1 << 2)) != 0) {
                value = -value;
            }
        }
    }

    if (table->index[read_index] != VALUE_INDEX_META && table->index[read_index] != VALUE_INDEX_DEBUG) {
        meters.update_value(slot, table->index[read_index], value);
    }

    read_index = (read_index + 1) % table->specs_length;

    if (read_index == 0) {
        // make a little pause after each round trip
        read_allowed = true;
    }

    prepare_read();

    if (!read_allowed) {
        start_generic_read();
    }
}
