/* esp32-firmware
 * Copyright (C) 2022 Erik Fleckstein <erik@tinkerforge.com>
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

import * as util from "../util";

import { h, Context, Fragment } from "preact";
import {useContext, useRef, useState} from "preact/hooks";
import { JSXInternal } from "preact/src/jsx";
import { Button, ButtonGroup } from "react-bootstrap";
import { Minus, Plus } from "react-feather";

interface InputFloatProps {
    idContext?: Context<string>
    value: number
    onValue: (value: number) => void
    digits: number
    unit: string
    min: number
    max: number
    showMinMax?: boolean
}

interface InputFloatReadonlyProps {
    idContext?: Context<string>
    value: number
    digits: number
    unit: string
}

export function InputFloat(props: InputFloatProps | InputFloatReadonlyProps) {
    let id = useContext(props.idContext);

    let pow10 = Math.pow(10, props.digits);

    const input = useRef<HTMLInputElement>();

    const [inputInFlight, setInputInFlight] = useState<string | null>(null);

    const setTarget = 'onValue' in props ? (target: number) => {
        target = util.clamp(props.min, target, props.max);
        input.current.parentNode.dispatchEvent(new Event('input', {bubbles: true}));
        props.onValue(target)
    } : (target: number) => {};

    // Firefox does not localize numbers with a fractional part correctly.
    // OTOH Webkit based browsers (correctly) expect setting the value to a non-localized number.
    // Unfortunately, setting the value to a localized number (i.e. with , instead of . for German)
    // does not raise an exception, instead only a warning on the console is shown.
    // So to make everyone happy, we use user agent detection.
    let propValue = navigator.userAgent.indexOf("Gecko/") >= 0
        ? util.toLocaleFixed(props.value / pow10, props.digits)
        : (props.value / pow10).toFixed(props.digits);

    // If a user is currently typing, we have to preserve the input
    // (even if it does currently not confirm to the number format).
    // Otherwise set value to the given property.
    let value = inputInFlight === null ? propValue : inputInFlight;

    return (
        <div class="input-group">
            <input class="form-control no-spin"
                       id={id}
                       type="number"
                       ref={input}
                       step={1/pow10}
                       onInput={'onValue' in props ? (e) => setInputInFlight((e.target as HTMLInputElement).value) : undefined}
                       onfocusout={'onValue' in props ? () => {
                            if (inputInFlight === null)
                                return;

                            let target = parseFloat(inputInFlight);
                            if (isNaN(target))
                                return;

                            target = util.clamp(props.min, target * pow10, props.max);
                            setTarget(target);
                            setInputInFlight(null);
                        } : undefined}
                       value={value}
                       disabled={!('onValue' in props)}
                       inputMode="decimal"/>
            <div class="input-group-append">
                <div class="form-control input-group-text">
                    {this.props.unit}
                </div>
                {'onValue' in props ?
                    <>
                        <Button variant="primary"
                                className="form-control px-1"
                                style="margin-right: .125rem !important;"
                                onClick={() => {
                                    let v = props.value;
                                    let target = (v % pow10 === 0) ? (v - pow10) : (v - (v % pow10));

                                    setTarget(target);
                                }}>
                            <Minus/>
                        </Button>
                        <Button variant="primary"
                                className="form-control px-1 rounded-right"
                                onClick={() => {
                                    let v = props.value;
                                    let target = (v - (v % pow10)) + pow10;

                                    setTarget(target);
                                }}>
                            <Plus/>
                        </Button>
                    </>
                    : <></>
                }
            </div>
            {!('onValue' in props) || !props.showMinMax ? null :
                <ButtonGroup className="flex-wrap">
                    <Button variant="primary"
                            className="ml-2"
                            style="margin-right: .125rem !important;"
                            onClick={() => {
                                setTarget(props.min);
                            }}
                            >
                        {(props.min / pow10).toString() + " " + props.unit}
                    </Button>
                    <Button variant="primary" onClick={() => {
                                setTarget(props.max);
                            }}
                            >
                        {(props.max / pow10).toString() + " " + props.unit}
                    </Button>
                </ButtonGroup>
            }
        </div>
    );
}
