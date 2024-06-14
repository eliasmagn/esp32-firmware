/** @jsxImportSource preact */
import { h } from "preact";
let x = {
    "meters_modbus_tcp": {
        "status": {
        },
        "navbar": {
        },
        "content": {
            "meter_class": "Modbus/TCP",

            "display_name": "Anzeigename",
            "host": "Host",
            "host_invalid": "Host ist ungültig",
            "port": "Port",
            "port_muted": "typischerweise 502",
            "table": "Registertabelle",
            "table_select": "Auswählen...",
            "table_custom": "Benutzerdefiniert",
            "table_sungrow_hybrid_inverter": "Sungrow Hybrid-Wechselrichter (SH...)",
            "table_sungrow_string_inverter": "Sungrow String-Wechselrichter (SG...)",
            "table_solarmax_max_storage": "Solarmax Max.Storage",
            "table_victron_energy_gx": "Victron Energy GX",
            "table_deye_hybrid_inverter": "Deye Hybrid-Wechselrichter",
            "table_alpha_ess_hybrid_inverter": "Alpha ESS Hybrid-Wechselrichter",
            "virtual_meter": "Virtueller Zähler",
            "virtual_meter_select": "Auswählen...",
            "virtual_meter_inverter": "Wechselrichter",
            "virtual_meter_grid": "Netzanschluss",
            "virtual_meter_battery": "Speicher",
            "virtual_meter_load": "Last",
            "device_address": "Geräteadresse",
            "device_address_muted": /*SFN*/(port: number) => "typischerweise " + port/*NF*/,
            "register_address_mode": "Adressmodus",
            "register_address_mode_select": "Auswählen...",
            "register_address_mode_address": "Registeradresse (beginnt bei 0)",
            "register_address_mode_number": "Registernummer (beginnt bei 1)",
            "registers": "Register",
            "registers_add_title": "Register hinzufügen",
            "registers_add_count": /*SFN*/(x: number, max: number) => x + " von " + max + " Registern konfiguriert"/*NF*/,
            "registers_add_select_address_mode": "Zuerst Adressmodus auswählen...",
            "registers_edit_title": "Register bearbeiten",
            "registers_register": /*SFN*/(start_address: number, value_id_name: string) => start_address + " als " + value_id_name/*NF*/,
            "registers_register_type": "Registertyp",
            "registers_register_type_select": "Auswählen...",
            "registers_register_type_holding_register": "Holding-Register",
            "registers_register_type_input_register": "Input-Register",
            "registers_start_address": "Startadresse",
            "registers_start_address_muted": "beginnt bei 0",
            "registers_start_number": "Startnummer",
            "registers_start_number_muted": "beginnt bei 1",
            "registers_value_type": "Werttyp",
            "registers_value_type_select": "Auswählen...",
            "registers_value_type_u16": "Ein Register, 16-Bit, Ganzzahl, vorzeichenlos",
            "registers_value_type_s16": "Ein Register, 16-Bit, Ganzzahl, vorzeichenbehaftet",
            "registers_value_type_u32be": "Zwei Register, 32-Bit, Ganzzahl, vorzeichenlos, Big-Endian",
            "registers_value_type_u32le": "Zwei Register, 32-Bit, Ganzzahl, vorzeichenlos, Little-Endian",
            "registers_value_type_s32be": "Zwei Register, 32-Bit, Ganzzahl, vorzeichenbehaftet, Big-Endian",
            "registers_value_type_s32le": "Zwei Register, 32-Bit, Ganzzahl, vorzeichenbehaftet, Little-Endian",
            "registers_value_type_f32be": "Zwei Register, 32-Bit, Gleitkommazahl, Big-Endian",
            "registers_value_type_f32le": "Zwei Register, 32-Bit, Gleitkommazahl, Little-Endian",
            "registers_value_type_u64be": "Vier Register, 64-Bit, Ganzzahl, vorzeichenlos, Big-Endian",
            "registers_value_type_u64le": "Vier Register, 64-Bit, Ganzzahl, vorzeichenlos, Little-Endian",
            "registers_value_type_s64be": "Vier Register, 64-Bit, Ganzzahl, vorzeichenbehaftet, Big-Endian",
            "registers_value_type_s64le": "Vier Register, 64-Bit, Ganzzahl, vorzeichenbehaftet, Little-Endian",
            "registers_value_type_f64be": "Vier Register, 64-Bit, Gleitkommazahl, Big-Endian",
            "registers_value_type_f64le": "Vier Register, 64-Bit, Gleitkommazahl, Little-Endian",
            "registers_offset": "Verschiebung",
            "registers_scale_factor": "Skalierfaktor",
            "registers_value_id": "Wert"
        },
        "script": {
        }
    }
}
