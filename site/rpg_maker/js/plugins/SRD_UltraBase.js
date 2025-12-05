/*:
 * @target MZ
 * @plugindesc Contains code required for HUD Maker Ultra. Does not affect the RPG Maker codebase.
 * @author SRDude
 * @url http://sumrndm.site
 * @orderBefore SRD_HUDMakerUltra
 *
 * @help
 * ============================================================================
 *                                  Ultra Base
 *                                 Version 1.2.0
 *                                    SRDude
 * ============================================================================
 *
 * The base plugin required for HUD Maker Ultra.
 *
 * Does not provide any functionality beyond that.
 *
 * ============================================================================
 *  End of Help File
 * ============================================================================
 *
 * Welcome to the bottom of the Help file. Thanks for reading!
 *
 * https://www.youtube.com/SumRndmDde
 * https://www.twitter.com/SumRndmDde
 * http://sumrndm.site
 *
 * Until next time,
 *   ~ SRDude
 */

var SRD = SRD || {};
SRD.UltraBase = SRD.UltraBase || {};

var Imported = Imported || {};
Imported.SRD_UltraBase = 0x010200; // 1.2.0

(function($) {

"use strict";

//=============================================================================
// * isPlaytest
// *
// * Checks if the game is being play-tested from the MZ editor.
//=============================================================================
$.isPlaytest = function() {
	return Utils.isNwjs() && Utils.isOptionValid("test");
}

//=============================================================================
// * dataFileExists
// *
// * Checks if a file with "fileName" exists in "data" folder.
//=============================================================================
$.dataFileExists = function(fileName) {
	if(Utils.isNwjs()) {
		const fs = require("fs");
		return fs.existsSync("data/plugin/" + fileName);
	}
	return true;
}

//=============================================================================
// * addDataFile
// *
// * Adds file to list of DataManager files. 
// * Returns false if could not be found.
//=============================================================================
$.addDataFile = function(varName, fileName) {
	if($.dataFileExists(fileName)) {
		if(!DataManager._databasePluginFiles_Ultra) {
			DataManager._databasePluginFiles_Ultra = [];
		}
		DataManager._databasePluginFiles_Ultra.push({ name: varName, src: fileName });
		return true;
	}
	return false;
}

//=============================================================================
// * printCustomCodeError
// *
// * Prints formatted code error.
//=============================================================================
$.printCustomCodeError = function(title, code, error) {
	const output = `
%c${title} - Custom Code Error

%c-- %cCode: %c--
${code}
-----------

%c-- %cError: %c--
${error}
------------
`;
	console.log(output, "font-weight: bold", "", "font-style: italic", "", "", "font-style: italic", "");
}

//=============================================================================
// * convertStringToFunc
// *
// * Converts a string to a function. If unsuccessful, prints error.
//=============================================================================
$.convertStringToFunc = function(funcString, title, params) {
	if(!funcString) {
		return null;
	}
	const functionArgs = !params ? [funcString] : [...params, funcString];
	let result = null;
	try {
		result = new Function(...functionArgs);
	} catch(e) {
		$.printCustomCodeError(title, funcString, e);
	}
	return result || null;
}

//=============================================================================
// * UltraSignal
// *
// * Calls all provided callbacks once triggered.
//=============================================================================
class UltraSignal {
	constructor() {
		this.initialize(...arguments);
	}

	initialize() {
		this.callbacks = null;
	}

	trigger() {
		if(this.callbacks !== null) {
			const len = this.callbacks.length;
			for(let i = 0; i < len; i++) {
				if(this.callbacks[i] !== null) {
					this.callbacks[i](...arguments);
				}
			}
		}
	}

	run(callback) {
		if(this.callbacks === null) {
			this.callbacks = [];
		}
		let freeSpot = -1;
		for(let i = 0; i < this.callbacks.length; i++) {
			if(this.callbacks[i] === null) {
				freeSpot = i;
				break;
			}
		}
		if(freeSpot >= 0) {
			this.callbacks[freeSpot] = callback;
			return freeSpot;
		}
		this.callbacks.push(callback);
		return this.callbacks.length - 1;
	}

	remove(id) {
		if(id >= 0 && id < this.callbacks.length) {
			this.callbacks[id] = null;
			if(this.isEmpty()) {
				this.clear();
			}
			return true;
		}
		return false;
	}

	isEmpty() {
		let result = true;
		for(let i = 0; i < this.callbacks.length; i++) {
			if(this.callbacks[i] !== null) {
				result = false;
				break;
			}
		}
		return result;
	}

	clear() {
		this.callbacks = null;
	}
}

//=============================================================================
// * UltraUtils
// *
// * Helpers functions for recurring data parsing patterns.
//=============================================================================
class UltraUtils {
	static getActor(sourceType, index) {
		if(sourceType) {
			return $gameActors.actor(index);
		} else {
			if(index >= 1 && index <= $gameParty._actors.length) {
				return $gameActors.actor($gameParty._actors[index - 1]);
			}
		}
		return null;
	}

	static getEnemy(sourceType, index) {
		if(sourceType) {
			let len = $gameTroop.members().length;
			for(let i = 0; i < len; i++) {
				const enemy = $gameTroop.members()[i];
				if(enemy.enemyId() === index) {
					return enemy;
				}
			}
		} else {
			if(index >= 1 && index <= $gameTroop.members().length) {
				return $gameTroop.members()[index - 1];
			}
		}
		return null;
	}

	static convertDirectionToText(dir) {
		switch(dir) {
			case 2: return "Down";
			case 4: return "Left";
			case 6: return "Right";
			case 8: return "Up";
		}
		return "";
	}

	static createOpacityColor(colorString, colorOpacity) {
		let result = "rgba(";
		for(let i = 0; i <= 2; i++) {
			result += parseInt(colorString.substring((i * 2) + 1, (i * 2) + 3), 16).toString();
			result += ", ";
		}
		result += colorOpacity.toString();
		result += ")";
		return result;
	}

	static hexTo255Array(colorString, opacityRatio) {
		let result = [];
		for(let i = 0; i <= 2; i++) {
			result.push(parseInt(colorString.substring((i * 2) + 1, (i * 2) + 3), 16));
		}
		result.push(opacityRatio * 255);
		return result;
	}

	static convertNumberAlignToText(num) {
		switch(num) {
			case 0: return "left";
			case 1: return "center";
			case 2: return "right";
		}
		return "center";
	}
}

//=============================================================================
// * UltraEasingCurveTypes
//=============================================================================

const UltraEasingCurveTypes = {
	Linear: 0,
	QuadraticEaseIn: 1,
	QuadraticEaseOut: 2,
	QuadraticEaseInOut: 3,
	CubicEaseIn: 4,
	CubicEaseOut: 5,
	CubicEaseInOut: 6,
	QuarticEaseIn: 7,
	QuarticEaseOut: 8,
	QuarticEaseInOut: 9,
	QuinticEaseIn: 10,
	QuinticEaseOut: 11,
	QuinticEaseInOut: 12,
	SineEaseIn: 13,
	SineEaseOut: 14,
	SineEaseInOut: 15,
	CircularEaseIn: 16,
	CircularEaseOut: 17,
	CircularEaseInOut: 18,
	ExponentialEaseIn: 19,
	ExponentialEaseOut: 20,
	ExponentialEaseInOut: 21,
	ElasticEaseIn: 22,
	ElasticEaseOut: 23,
	ElasticEaseInOut: 24,
	BackEaseIn: 25,
	BackEaseOut: 26,
	BackEaseInOut: 27,
	BounceEaseIn: 28,
	BounceEaseOut: 29,
	BounceEaseInOut: 30
}

//=============================================================================
// * UltraEasingCurve
//=============================================================================
class UltraEasingCurve {
	constructor() {
		this.initialize(...arguments);
	}

	initialize(easingType) {
		if(!UltraEasingCurve.M_PI_2) {
			UltraEasingCurve.M_PI_2 = (Math.PI / 2.0);
		}
		this._easing = UltraEasingCurve.getEasingFunction(easingType);
	}

	getValue(value) {
		if(this._easing !== null) {
			return this._easing(value);
		}
		return value;
	}

	static getEasingFunction(easingType) {
		switch(easingType) {
			case UltraEasingCurveTypes.QuadraticEaseIn: return UltraEasingCurve.quadraticEaseIn;
			case UltraEasingCurveTypes.QuadraticEaseOut: return UltraEasingCurve.quadraticEaseOut;
			case UltraEasingCurveTypes.QuadraticEaseInOut: return UltraEasingCurve.quadraticEaseInOut;
			case UltraEasingCurveTypes.CubicEaseIn: return UltraEasingCurve.cubicEaseIn;
			case UltraEasingCurveTypes.CubicEaseOut: return UltraEasingCurve.cubicEaseOut;
			case UltraEasingCurveTypes.CubicEaseInOut: return UltraEasingCurve.cubicEaseInOut;
			case UltraEasingCurveTypes.QuarticEaseIn: return UltraEasingCurve.quarticEaseIn;
			case UltraEasingCurveTypes.QuarticEaseOut: return UltraEasingCurve.quarticEaseOut;
			case UltraEasingCurveTypes.QuarticEaseInOut: return UltraEasingCurve.quarticEaseInOut;
			case UltraEasingCurveTypes.QuinticEaseIn: return UltraEasingCurve.quinticEaseIn;
			case UltraEasingCurveTypes.QuinticEaseOut: return UltraEasingCurve.quinticEaseOut;
			case UltraEasingCurveTypes.QuinticEaseInOut: return UltraEasingCurve.quinticEaseInOut;
			case UltraEasingCurveTypes.SineEaseIn: return UltraEasingCurve.sineEaseIn;
			case UltraEasingCurveTypes.SineEaseOut: return UltraEasingCurve.sineEaseOut;
			case UltraEasingCurveTypes.SineEaseInOut: return UltraEasingCurve.sineEaseInOut;
			case UltraEasingCurveTypes.CircularEaseIn: return UltraEasingCurve.circularEaseIn;
			case UltraEasingCurveTypes.CircularEaseOut: return UltraEasingCurve.circularEaseOut;
			case UltraEasingCurveTypes.CircularEaseInOut: return UltraEasingCurve.circularEaseInOut;
			case UltraEasingCurveTypes.ExponentialEaseIn: return UltraEasingCurve.exponentialEaseIn;
			case UltraEasingCurveTypes.ExponentialEaseOut: return UltraEasingCurve.exponentialEaseOut;
			case UltraEasingCurveTypes.ExponentialEaseInOut: return UltraEasingCurve.exponentialEaseInOut;
			case UltraEasingCurveTypes.ElasticEaseIn: return UltraEasingCurve.elasticEaseIn;
			case UltraEasingCurveTypes.ElasticEaseOut: return UltraEasingCurve.elasticEaseOut;
			case UltraEasingCurveTypes.ElasticEaseInOut: return UltraEasingCurve.elasticEaseInOut;
			case UltraEasingCurveTypes.BackEaseIn: return UltraEasingCurve.backEaseIn;
			case UltraEasingCurveTypes.BackEaseOut: return UltraEasingCurve.backEaseOut;
			case UltraEasingCurveTypes.BackEaseInOut: return UltraEasingCurve.backEaseInOut;
			case UltraEasingCurveTypes.BounceEaseIn: return UltraEasingCurve.bounceEaseIn;
			case UltraEasingCurveTypes.BounceEaseOut: return UltraEasingCurve.bounceEaseOut;
			case UltraEasingCurveTypes.BounceEaseInOut: return UltraEasingCurve.bounceEaseInOut;
		}
		return null;
	}

	static invertEasing(v) {
		if(v === 0 || v % 3 === 0) {
			return v;
		}
		return v % 3 === 1 ? v + 1 : v - 1;
	}

	static linear(v) {
		return v;
	}

	static quadraticEaseIn(v) {
		return v * v;
	}

	static quadraticEaseOut(v) {
		return -(v * (v - 2));
	}

	static quadraticEaseInOut(v) {
		if(v < 0.5) {
			return 2 * v * v;
		} else {
			return (-2 * v * v) + (4 * v) - 1;
		}
	}

	static cubicEaseIn(v) {
		return v * v * v;
	}

	static cubicEaseOut(v) {
		const f = (v - 1);
		return f * f * f + 1;
	}

	static cubicEaseInOut(v) {
		if(v < 0.5) {
			return 4 * v * v * v;
		} else {
			const f = ((2 * v) - 2);
			return 0.5 * f * f * f + 1;
		}
	}

	static quarticEaseIn(v) {
		return v * v * v * v;
	}

	static quarticEaseOut(v) {
		const f = (v - 1);
		return f * f * f * (1 - v) + 1;
	}

	static quarticEaseInOut(v) {
		if(v < 0.5) {
			return 8 * v * v * v * v;
		} else {
			const f = (v - 1);
			return -8 * f * f * f * f + 1;
		}
	}

	static quinticEaseIn(v) {
		return v * v * v * v * v;
	}

	static quinticEaseOut(v) {
		const f = (v - 1);
		return f * f * f * f * f + 1;
	}

	static quinticEaseInOut(v) {
		if(v < 0.5) {
			return 16 * v * v * v * v * v;
		} else {
			const f = ((2 * v) - 2);
			return 0.5 * f * f * f * f * f + 1;
		}
	}

	static sineEaseIn(v) {
		return Math.sin((v - 1) * this.M_PI_2) + 1;
	}

	static sineEaseOut(v) {
		return Math.sin(v * this.M_PI_2);
	}

	static sineEaseInOut(v) {
		return 0.5 * (1 - Math.cos(v * Math.PI));
	}

	static circularEaseIn(v) {
		return 1 - Math.sqrt(1 - (v * v));
	}

	static circularEaseOut(v) {
		return Math.sqrt((2 - v) * v);
	}

	static circularEaseInOut(v) {
		if(v < 0.5) {
			return 0.5 * (1 - Math.sqrt(1 - 4 * (v * v)));
		} else {
			return 0.5 * (Math.sqrt(-((2 * v) - 3) * ((2 * v) - 1)) + 1);
		}
	}

	static exponentialEaseIn(v) {
		return (v === 0.0) ? v : Math.pow(2, 10 * (v - 1));
	}

	static exponentialEaseOut(v) {
		return (v === 1.0) ? v : 1 - Math.pow(2, -10 * v);
	}

	static exponentialEaseInOut(v) {
		if(v === 0.0 || v === 1.0) return v;
		if(v < 0.5) {
			return 0.5 * Math.pow(2, (20 * v) - 10);
		} else {
			return -0.5 * Math.pow(2, (-20 * v) + 10) + 1;
		}
	}

	static elasticEaseIn(v) {
		return Math.sin(13 * this.M_PI_2 * v) * Math.pow(2, 10 * (v - 1));
	}

	static elasticEaseOut(v) {
		return Math.sin(-13 * this.M_PI_2 * (v + 1)) * Math.pow(2, -10 * v) + 1;
	}

	static elasticEaseInOut(v) {
		if(v < 0.5) {
			return 0.5 * Math.sin(13 * this.M_PI_2 * (2 * v)) * Math.pow(2, 10 * ((2 * v) - 1));
		} else {
			return 0.5 * (Math.sin(-13 * this.M_PI_2 * ((2 * v - 1) + 1)) * Math.pow(2, -10 * (2 * v - 1)) + 2);
		}
	}

	static backEaseIn(v) {
		return v * v * v - v * Math.sin(v * Math.PI);
	}

	static backEaseOut(v) {
		const f = (1 - v);
		return 1 - (f * f * f - f * Math.sin(f * Math.PI));
	}

	static backEaseInOut(v) {
		if(v < 0.5) {
			const f = 2 * v;
			return 0.5 * (f * f * f - f * Math.sin(f * Math.PI));
		} else {
			const f = (1 - (2 * v - 1));
			return 0.5 * (1 - (f * f * f - f * Math.sin(f * Math.PI))) + 0.5;
		}
	}

	static bounceEaseIn(v) {
		return 1 - UltraEasingCurve.bounceEaseOut(1 - v);
	}

	static bounceEaseOut(v) {
		if(v < 4 / 11.0) {
			return (121 * v * v) / 16.0;
		} else if(v < 8 / 11.0) {
			return (363 / 40.0 * v * v) - (99 / 10.0 * v) + 17 / 5.0;
		} else if(v < 9 / 10.0) {
			return (4356 / 361.0 * v * v) - (35442 / 1805.0 * v) + 16061 / 1805.0;
		} else {
			return (54 / 5.0 * v * v) - (513 / 25.0 * v) + 268 / 25.0;
		}
	}

	static bounceEaseInOut(v) {
		if(v < 0.5) {
			return 0.5 * UltraEasingCurve.bounceEaseIn(v * 2);
		} else {
			return 0.5 * UltraEasingCurve.bounceEaseOut(v * 2 - 1) + 0.5;
		}
	}
}

//=============================================================================
// * UltraProcessConfiguration
// *
// * Used to configure the behavior of dynamic processes.
//=============================================================================
class UltraProcessConfiguration {
	constructor() {
		this.initialize(...arguments);
	}

	initialize() {
	}

	processDynamicInput(data, isNumber) {
		if(typeof data === "object") {
			return this.processDynamicData(data, isNumber);
		}
		return data;
	}

	processDynamicData(data, isNumber) {
		return isNumber ? 0 : "";
	}

	getProcessTitle() {
		return "Ultra Base";
	}

	getCustomFunctionParams() {
		return null;
	}

	createCustomFunction(codeString, extraParams, self) {
		const params = this._getCustomFunctionParameters(extraParams);
		const funcParamsExist = params.exists;
		const funcParams = params.params;
		let result = this._createCustomFunctionInternal(codeString, funcParamsExist ? funcParams[0] : null);
		if(result !== null && funcParamsExist) {
			result = result.bind.apply(result, [self].concat(funcParams[1]));
		}
		return result;
	}

	_getCustomFunctionParameters(extraParams) {
		let funcParams = this.getCustomFunctionParams();
		let funcParamsExist = funcParams !== null && funcParams.length >= 2;
		if(extraParams !== null && extraParams.length > 0) {
			if(funcParamsExist) funcParams[0] = funcParams[0].concat(extraParams);
			else {
				funcParamsExist = true;
				funcParams = [extraParams, []];
			}
		}
		return { params: funcParams, exists: funcParamsExist };
	}

	_createCustomFunctionInternal(codeString, funcParams) {
		const funcConstructorArgs = funcParams !== null ? [...funcParams, codeString] : [codeString];
		let result = null;
		try {
			result = new Function(...funcConstructorArgs);
		} catch(e) {
			$.printCustomCodeError(this.getProcessTitle(), codeString, e);
		}
		return result || null;
	}
}

//=============================================================================
// * UltraDynamicCondition
// *
// * Dynamically checks and updates condition based on provided data.
//=============================================================================
class UltraDynamicCondition {
	constructor() {
		this.initialize(...arguments);
	}

	initialize(conditionData, config) {
		this.createPublicFields();
		this.createPrivateFields(conditionData, config);
	}

	createPublicFields() {
		this.onChange = new UltraSignal();
		this.state = null;
	}

	createPrivateFields(conditionData, config) {
		this._data = conditionData;
		this._config = config;
		this._type = this._data.Type;
		this._component = null;
		this._updateComponent = null;
	}

	start() {
		this.createComponent();
		this.createUpdateComponent();
	}

	createComponent() {
		switch(this._type) {
			case 0: { this._component = new UltraDynamicCondition_SwitchComponent(this._data, this); break; }
			case 1: { this._component = new UltraDynamicCondition_VariableComponent(this._data, this); break; }
			case 2: { this._component = new UltraDynamicCondition_ActorComponent(this._data, this); break; }
			case 3: { this._component = new UltraDynamicCondition_EnemyComponent(this._data, this); break; }
			case 4: { this._component = new UltraDynamicCondition_PlayerDirectionComponent(this._data, this); break; }
			case 5: { this._component = new UltraDynamicCondition_GoldComponent(this._data, this); break; }
			case 6: { this._component = new UltraDynamicCondition_ButtonComponent(this._data, this); break; }
			case 7: { this._component = new UltraDynamicCondition_InventoryComponent(this._data, this); break; }
			case 8: { this._component = new UltraDynamicCondition_OtherComponent(this._data, this); break; }
			case 9: { this._component = new UltraDynamicCondition_CodeComponent(this._data, this); break; }
			case 12: { this._component = new UltraDynamicCondition_NumberCompareComponent(this._data, this); break; }
			case 13: { this._component = new UltraDynamicCondition_TextCompareComponent(this._data, this); break; }
		}
	}

	createUpdateComponent() {
		if(this._component != null) {
			this._updateComponent = this._component.getUpdateComponent();
		}
	}

	setState(val) {
		if(this.state !== val) {
			this.state = val;
			this.onChange.trigger(this.state);
		}
	}

	update() {
		if(this._updateComponent !== null) {
			this._updateComponent.update(...arguments);
		}
	}

	destroy() {
		if(this._component !== null) {
			this._component.destroy();
		}
	}

	getConfig() {
		return this._config;
	}
}

//=============================================================================
// * UltraDynamicMutliCondition
// *
// * Works like UltraDynamicCondition, but takes an array of condition data.
// * All conditions must be true for this to signal `true`. Otherwise, it will be `false`.
//=============================================================================

class UltraDynamicMultiCondition {
	constructor() {
		this.initialize(...arguments);
	}

	initialize(conditionDataArray, config) {
		this.createPublicFields();
		this.setupConditions(conditionDataArray, config);
	}

	createPublicFields() {
		this.onChange = new UltraSignal();
		this.state = null;
	}

	setupConditions(conditionDataArray, config) {
		this.conditions = [];
		for(let i = 0; i < conditionDataArray.length; i++) {
			const conditionObj = new UltraDynamicCondition(conditionDataArray[i], config);
			conditionObj.onChange.run(this.checkForChange.bind(this));
			this.conditions.push(conditionObj);
		}
	}

	start() {
		for(let i = 0; i < this.conditions.length; i++) {
			this.conditions[i].start();
		}
	}

	checkForChange() {
		let result = true;
		for(let i = 0; i < this.conditions.length; i++) {
			if(!this.conditions[i].state) {
				result = false;
				break;
			}
		}
		this.setState(result);
	}

	setState(val) {
		if(this.state !== val) {
			this.state = val;
			this.onChange.trigger(this.state);
		}
	}

	update() {
		for(let i = 0; i < this.conditions.length; i++) {
			this.conditions[i].update(...arguments);
		}
	}

	destroy() {
		for(let i = 0; i < this.conditions.length; i++) {
			this.conditions[i].destroy();
		}
		this.conditions = [];
	}
}

//=============================================================================
// * UltraDynamicCondition_BaseComponent
//=============================================================================
class UltraDynamicCondition_BaseComponent {
	constructor() {
		this.initialize(...arguments);
	}

	initialize(conditionData, dynamicCondition) {
		this._data = conditionData;
		this._parent = dynamicCondition;
		this.createFields();
		if(this.verify()) {
			this.start();
		}
	}

	createFields() {
	}

	verify() {
		return false;
	}

	start() {
	}

	checkForChange() {
	}

	getUpdateComponent() {
		return null;
	}

	update() {
	}

	destroy() {
	}
}

//=============================================================================
// * UltraDynamicCondition_SwitchComponent
//=============================================================================
class UltraDynamicCondition_SwitchComponent extends UltraDynamicCondition_BaseComponent {
	createFields() {
		this._id = this._data.ID;
		this._value = this._data.Value;
		this._previousValue = null;
		this._destroyId = null;
	}

	start() {
		this.checkForChange();
		this._destroyId = UltraTriggerManager.onSwitchChanged.run(this.checkForChange.bind(this));
	}

	verify() {
		return this._id >= 1 && this._id < $dataSystem.switches.length;
	}

	checkForChange() {
		const newValue = $gameSwitches.value(this._id);
		if(this._previousValue !== newValue) {
			this._previousValue = newValue;
			this._parent.setState(this._value === this._previousValue);
		}
	}

	destroy() {
		if(this._destroyId !== null) {
			UltraTriggerManager.onSwitchChanged.remove(this._destroyId);
		}
	}
}

//=============================================================================
// * UltraDynamicCondition_VariableComponent
//=============================================================================
class UltraDynamicCondition_VariableComponent extends UltraDynamicCondition_BaseComponent {
	createFields() {
		this._id = this._data.ID;
		this._operator = this._data.Op;
		this._value = this._parent.getConfig().processDynamicInput(this._data.Value || 0, true);
		this._previousValue = null;
		this._destroyId = null;
	}

	start() {
		this.checkForChange();
		this._destroyId = UltraTriggerManager.onVariableChanged.run(this.checkForChange.bind(this));
	}

	verify() {
		return this._id >= 1 && this._id < $dataSystem.variables.length && this._operator >= 0 && this._operator < 6;
	}

	checkForChange() {
		const newValue = $gameVariables.value(this._id);
		if(this._previousValue !== newValue) {
			this._previousValue = newValue;
			let comp = false;
			switch(this._operator) {
				case 0: { comp = this._previousValue === this._value; break; }
				case 1: { comp = this._previousValue !== this._value; break; }
				case 2: { comp = this._previousValue <= this._value; break; }
				case 3: { comp = this._previousValue >= this._value; break; }
				case 4: { comp = this._previousValue < this._value; break; }
				case 5: { comp = this._previousValue > this._value; break; }
			}
			this._parent.setState(comp);
		}
	}

	destroy() {
		if(this._destroyId !== null) {
			UltraTriggerManager.onVariableChanged.remove(this._destroyId);
		}
	}
}

//=============================================================================
// * UltraDynamicCondition_ActorComponent
//=============================================================================
class UltraDynamicCondition_ActorComponent extends UltraDynamicCondition_BaseComponent {
	createFields() {
		this._actorType = this._data.ActorType;
		this._actorIndex = this._actorType ? this._data.Actor : this._parent.getConfig().processDynamicInput(this._data.Actor || 0, true);
		this._check = this._data.Check;
		this._value = this._check === 1 ? this._data.Name : this._data.ID;
	}

	start() {
		switch(this._check) {
			case 0: { this.checkForChange = this.checkExists; break; }
			case 1: { this.checkForChange = this.checkName; break; }
			case 2: { this.checkForChange = this.checkClass; break; }
			case 3: { this.checkForChange = this.checkSkill; break; }
			case 4: { this.checkForChange = this.checkWeapon; break; }
			case 5: { this.checkForChange = this.checkArmor; break; }
			case 6: { this.checkForChange = this.checkState; break; }
		}
		this.checkForChange();
	}

	verify() {
		return this._actorIndex >= 1;
	}

	getActor() {
		return UltraUtils.getActor(this._actorType, this._actorIndex);
	}

	checkExists() {
		if(this._actorType) {
			this._parent.setState($gameParty.members().includes($gameActors.actor(this._actorIndex)));
		} else {
			this._parent.setState(this._actorIndex >= 1 && this._actorIndex <= $gameParty._actors.length);
		}
	}

	checkName() {
		const actor = this.getActor();
		if(actor !== null) {
			this._parent.setState(actor.name() === this._value);
		}
	}

	checkClass() {
		const actor = this.getActor();
		if(actor !== null) {
			this._parent.setState(actor._classId === this._value);
		}
	}

	checkSkill() {
		const actor = this.getActor();
		if(actor !== null) {
			this._parent.setState(actor.hasSkill(this._value));
		}
	}

	checkWeapon() {
		const actor = this.getActor();
		if(actor !== null) {
			this._parent.setState(actor.hasWeapon($dataWeapons[this._value]));
		}
	}

	checkArmor() {
		const actor = this.getActor();
		if(actor !== null) {
			this._parent.setState(actor.hasArmor($dataArmors[this._value]));
		}
	}

	checkState() {
		const actor = this.getActor();
		if(actor !== null) {
			this._parent.setState(actor.isStateAffected(this._value));
		}
	}

	checkForChange() {
	}

	getUpdateComponent() {
		return this;
	}

	update() {
		this.checkForChange();
	}
}

//=============================================================================
// * UltraDynamicCondition_EnemyComponent
//=============================================================================
class UltraDynamicCondition_EnemyComponent extends UltraDynamicCondition_BaseComponent {
	createFields() {
		this._enemyType = this._data.EnemyType;
		this._enemyIndex = this._enemyType ? this._data.Enemy : this._parent.getConfig().processDynamicInput(this._data.Enemy || 0, true);
		this._check = this._data.Check;
		this._value = this._data.ID || 1;
	}

	start() {
		switch(this._check) {
			case 0: { this.checkForChange = this.checkExists; break; }
			case 1: { this.checkForChange = this.checkState; break; }
		}
		this.checkForChange();
	}

	verify() {
		return this._enemyIndex >= 1;
	}

	getEnemy() {
		return UltraUtils.getEnemy(this._enemyType, this._enemyIndex);
	}

	checkExists() {
		this._parent.setState(this.getEnemy() !== null);
	}

	checkState() {
		const enemy = this.getEnemy()
		if(enemy !== null) {
			this._parent.setState(enemy.isStateAffected(this._value));
		}
	}

	checkForChange() {
	}

	getUpdateComponent() {
		return this;
	}

	update() {
		this.checkForChange();
	}
}

//=============================================================================
// * UltraDynamicCondition_PlayerDirectionComponent
//=============================================================================
class UltraDynamicCondition_PlayerDirectionComponent extends UltraDynamicCondition_BaseComponent {
	createFields() {
		this._direction = this._data.State;
	}

	start() {
		if($gamePlayer) {
			this.checkForChange();
		}
	}

	verify() {
		return this._enemyIndex >= 1;
	}

	checkForChange() {
		this._parent.setState($gamePlayer.direction() === this._direction);
	}

	getUpdateComponent() {
		return this;
	}

	update() {
		this.checkForChange();
	}
}

//=============================================================================
// * UltraDynamicCondition_GoldComponent
//=============================================================================
class UltraDynamicCondition_GoldComponent extends UltraDynamicCondition_BaseComponent {
	createFields() {
		this._operator = this._data.Op;
		this._value = this._parent.getConfig().processDynamicInput(this._data.Value || 0, true);
		this._destroyId = null;
	}

	start() {
		this.checkForChange();
		this._destroyId = UltraTriggerManager.onGoldChanged.run(this.checkForChange.bind(this));
	}

	verify() {
		return !!$gameParty;
	}

	checkForChange() {
		let comp = false;
		const gold = $gameParty.gold();
		switch(this._operator) {
			case 0: { comp = gold === this._value; break; }
			case 1: { comp = gold !== this._value; break; }
			case 2: { comp = gold <= this._value; break; }
			case 3: { comp = gold >= this._value; break; }
			case 4: { comp = gold < this._value; break; }
			case 5: { comp = gold > this._value; break; }
		}
		this._parent.setState(comp);
	}

	destroy() {
		if(this._destroyId !== null) {
			UltraTriggerManager.onGoldChanged.remove(this._destroyId);
		}
	}
}

//=============================================================================
// * UltraDynamicCondition_ButtonComponent
//=============================================================================
class UltraDynamicCondition_ButtonComponent extends UltraDynamicCondition_BaseComponent {
	createFields() {
		this._key = this._data.Key;
		this._state = this._data.State;
		this._button = this.getButtonString();
	}

	getButtonString() {
		switch(this._key) {
			case 0: return "ok";
			case 1: return "escape";
			case 2: return "shift";
			case 3: return "down";
			case 4: return "left";
			case 5: return "right";
			case 6: return "up";
		}
		return "";
	}

	start() {
		switch(this._state) {
			case 0: { this.checkForChange = this.checkIsPressed; break; }
			case 1: { this.checkForChange = this.checkIsNotPressed; break; }
			case 2: { this.checkForChange = this.checkWasJustPressed; break; }
			case 3: { this.checkForChange = this.checkIsRepeated; break; }
		}
		this.checkForChange();
	}

	verify() {
		return this._button !== "" && this._state >= 0 && this._state < 4;
	}

	checkIsPressed() {
		this._parent.setState(Input.isPressed(this._button));
	}

	checkIsNotPressed() {
		this._parent.setState(!Input.isPressed(this._button));
	}

	checkWasJustPressed() {
		this._parent.setState(Input.isTriggered(this._button));
	}

	checkIsRepeated() {
		this._parent.setState(Input.isRepeated(this._button));
	}

	getUpdateComponent() {
		return this;
	}

	update() {
		this.checkForChange();
	}
}

//=============================================================================
// * UltraDynamicCondition_InventoryComponent
//=============================================================================
class UltraDynamicCondition_InventoryComponent extends UltraDynamicCondition_BaseComponent {
	createFields() {
		this._check = this._data.Check;
		this._id = this._data.ID;
		this._destroyId = null;
	}

	start() {
		switch(this._check) {
			case 0: { this.checkForChange = this.checkItems; break; }
			case 1: { this.checkForChange = this.checkWeapons; break; }
			case 2: { this.checkForChange = this.checkArmors; break; }
		}
		this.checkForChange();
		this._destroyId = UltraTriggerManager.onItemCountChanged.run(this.checkForChange.bind(this));
	}

	verify() {
		switch(this._check) {
			case 0: return this._id >= 1 && this._id < $dataItems.length;
			case 1: return this._id >= 1 && this._id < $dataWeapons.length;
			case 2: return this._id >= 1 && this._id < $dataArmors.length;
		}
		return false;
	}

	checkItems() {
		this._parent.setState($gameParty.hasItem($dataItems[this._id]));
	}

	checkWeapons() {
		this._parent.setState($gameParty.hasItem($dataWeapons[this._id], true));
	}

	checkArmors() {
		this._parent.setState($gameParty.hasItem($dataArmors[this._id], true));
	}

	destroy() {
		if(this._destroyId !== null) {
			UltraTriggerManager.onItemCountChanged.remove(this._destroyId);
		}
	}
}

//=============================================================================
// * UltraDynamicCondition_NumberCompareComponent
//=============================================================================
class UltraDynamicCondition_NumberCompareComponent extends UltraDynamicCondition_BaseComponent {
	createFields() {
		this._operator = this._data.Op;
	}

	start() {
		this._dynamicNumber1 = new UltraDynamicNumber(this._data.Number1, this._parent.getConfig());
		this._dynamicNumber1.onChange.run(this.checkForChange.bind(this));
		this._dynamicNumber1.start();

		this._dynamicNumber2 = new UltraDynamicNumber(this._data.Number2, this._parent.getConfig());
		this._dynamicNumber2.onChange.run(this.checkForChange.bind(this));
		this._dynamicNumber2.start();

		this.checkForChange();
	}

	verify() {
		return !!this._data.Number1 && !!this._data.Number2;
	}

	checkForChange() {
		let comp = false;
		if(this._dynamicNumber1 && this._dynamicNumber2) {
			const one = this._dynamicNumber1.currentNumber;
			const two = this._dynamicNumber2.currentNumber;
			switch(this._operator) {
				case 0: { comp = one === two; break; }
				case 1: { comp = one !== two; break; }
				case 2: { comp = one <= two; break; }
				case 3: { comp = one >= two; break; }
				case 4: { comp = one < two; break; }
				case 5: { comp = one > two; break; }
			}
		}
		this._parent.setState(comp);
	}

	getUpdateComponent() {
		return this;
	}

	update() {
		if(this._dynamicNumber1 !== null) {
			this._dynamicNumber1.update();
		}
		if(this._dynamicNumber2 !== null) {
			this._dynamicNumber2.update();
		}
	}

	destroy() {
		if(this._dynamicNumber1 !== null) {
			this._dynamicNumber1.destroy();
			this._dynamicNumber1 = null;
		}
		if(this._dynamicNumber2 !== null) {
			this._dynamicNumber2.destroy();
			this._dynamicNumber2 = null;
		}
	}
}

//=============================================================================
// * UltraDynamicCondition_TextCompareComponent
//=============================================================================
class UltraDynamicCondition_TextCompareComponent extends UltraDynamicCondition_BaseComponent {
	createFields() {
		this._operator = this._data.Op;
	}

	start() {
		this._dynamicText1 = new UltraDynamicText(this._data.Text1, this._parent.getConfig());
		this._dynamicText1.onChange.run(this.checkForChange.bind(this));
		this._dynamicText1.start();

		this._dynamicText2 = new UltraDynamicText(this._data.Text2, this._parent.getConfig());
		this._dynamicText2.onChange.run(this.checkForChange.bind(this));
		this._dynamicText2.start();

		this.checkForChange();
	}

	verify() {
		return !!this._data.Text1 && !!this._data.Text2;
	}

	checkForChange() {
		let comp = false;
		if(this._dynamicText1 && this._dynamicText2) {
			const one = this._dynamicText1.currentText;
			const two = this._dynamicText2.currentText;
			switch(this._operator) {
				case 0: { comp = one === two; break; }
				case 1: { comp = one !== two; break; }
			}
		}
		this._parent.setState(comp);
	}

	getUpdateComponent() {
		return this;
	}

	update() {
		if(this._dynamicText1 !== null) {
			this._dynamicText1.update();
		}
		if(this._dynamicText2 !== null) {
			this._dynamicText2.update();
		}
	}

	destroy() {
		if(this._dynamicText1 !== null) {
			this._dynamicText1.destroy();
			this._dynamicText1 = null;
		}
		if(this._dynamicText2 !== null) {
			this._dynamicText2.destroy();
			this._dynamicText2 = null;
		}
	}
}

//=============================================================================
// * UltraDynamicCondition_OtherComponent
//=============================================================================
class UltraDynamicCondition_OtherComponent extends UltraDynamicCondition_BaseComponent {
	createFields() {
		this._check = this._data.Check;
	}

	verify() {
		return this._check >= 0 && this._check < 4;
	}

	start() {
		switch(this._check) {
			case 0: { this.checkForChange = this.checkForChange_playtest; break; }
			case 1: { this.checkForChange = this.checkForChange_inBattle; break; }
			case 2: { this.checkForChange = this.checkForChange_onMap; break; }
			case 3: { this.checkForChange = this.checkForChange_partyOverlay; break; }
		}
		this.checkForChange();
	}

	checkForChange_playtest() {
		this._parent.setState($gameTemp.isPlaytest());
	}

	checkForChange_inBattle() {
		this._parent.setState($gameParty.inBattle());
	}

	checkForChange_onMap() {
		this._parent.setState(!$gameParty.inBattle());
	}

	checkForChange_partyOverlay() {
		const component = arguments[0];
		if(component && component.isOverlayCoordinates) {
			const allCharacters = [$gamePlayer].concat($gamePlayer.followers().visibleFollowers());
			let result = false;
			for(let i = 0; i < allCharacters.length; i++) {
				const character = allCharacters[i];
				if(component.isOverlayCoordinates(character.screenX(), character.screenY(), -$gameMap.tileHeight())) {
					result = true;
					break;
				}
			}
			this._parent.setState(result);
		} else {
			this._parent.setState(false);
		}
	}

	getUpdateComponent() {
		return this;
	}

	update() {
		this.checkForChange(...arguments);
	}
}

//=============================================================================
// * UltraDynamicCondition_CodeComponent
//=============================================================================
class UltraDynamicCondition_CodeComponent extends UltraDynamicCondition_BaseComponent {
	createFields() {
		this._func = this._parent.getConfig().createCustomFunction(this._data.Code, null, this);
	}

	start() {
		this.checkForChange();
	}

	verify() {
		return this._func !== null;
	}

	checkForChange() {
		if(this._func !== null) {
			this._parent.setState(this._func());
		}
	}

	getUpdateComponent() {
		return this;
	}

	update() {
		this.checkForChange();
	}
}

//=============================================================================
// * UltraDynamicValueTypes
//=============================================================================
const UltraDynamicValueTypes = {
	TEXT: 0,
	NUMBER: 1,
	ACTORID: 2
};

//=============================================================================
// * UltraDynamicText
// *
// * Dynamically updates text based on provided data.
//=============================================================================
class UltraDynamicText {
	constructor() {
		this.initialize(...arguments);
	}

	initialize(textData, config) {
		this.createPublicFields();
		this.createPrivateFields(textData, config);
	}

	createPublicFields() {
		this.onChange = new UltraSignal();
		this.currentText = null;
	}

	createPrivateFields(textData, config) {
		this._data = textData;
		this._config = config;
		this._type = this._data.Type;
		this._component = null;
		this._updateComponent = null;
	}

	start() {
		this.createComponent();
		this.createUpdateComponent();
	}

	createComponent() {
		switch(this._type) {
			case 0: { this._component = new UltraDynamicValue_StaticComponent(    this._data, this, UltraDynamicValueTypes.TEXT); break; }
			case 1: { this._component = new UltraDynamicValue_GeneralComponent(   this._data, this, UltraDynamicValueTypes.TEXT); break; }
			case 2: { this._component = new UltraDynamicValue_SwitchComponent(    this._data, this, UltraDynamicValueTypes.TEXT); break; }
			case 3: { this._component = new UltraDynamicValue_VariableComponent(  this._data, this, UltraDynamicValueTypes.TEXT); break; }
			case 4: { this._component = new UltraDynamicValue_ActorComponent(     this._data, this, UltraDynamicValueTypes.TEXT); break; }
			case 5: { this._component = new UltraDynamicValue_EnemyComponent(     this._data, this, UltraDynamicValueTypes.TEXT); break; }
			case 6: { this._component = new UltraDynamicValue_InventoryComponent( this._data, this, UltraDynamicValueTypes.TEXT); break; }
			case 7: { this._component = new UltraDynamicValue_CodeComponent(      this._data, this, UltraDynamicValueTypes.TEXT); break; }
		}
	}

	createUpdateComponent() {
		if(this._component != null) {
			this._updateComponent = this._component.getUpdateComponent();
		}
	}

	setText(val) {
		if(this.currentText !== val) {
			this.currentText = val;
			this.onChange.trigger(this.currentText);
		}
	}

	update() {
		if(this._updateComponent !== null) {
			this._updateComponent.update();
		}
	}

	destroy() {
		if(this._component !== null) {
			this._component.destroy();
		}
	}

	getConfig() {
		return this._config;
	}
}

//=============================================================================
// * UltraDynamicNumber
// *
// * Dynamically updates number value based on provided data.
//=============================================================================
class UltraDynamicNumber {
	constructor() {
		this.initialize(...arguments);
	}

	initialize(textData, config) {
		this.createPublicFields();
		this.createPrivateFields(textData, config);
	}

	createPublicFields() {
		this.onChange = new UltraSignal();
		this.currentNumber = null;
	}

	createPrivateFields(textData, config) {
		this._data = textData;
		this._config = config;
		this._type = this._data.Type;
		this._component = null;
		this._updateComponent = null;
	}

	start() {
		this.createComponent();
		this.createUpdateComponent();
	}

	createComponent() {
		switch(this._type) {
			case 0: { this._component = new UltraDynamicValue_StaticComponent(    this._data, this, UltraDynamicValueTypes.NUMBER); break; }
			case 1: { this._component = new UltraDynamicValue_GeneralComponent(   this._data, this, UltraDynamicValueTypes.NUMBER); break; }
			case 2: { this._component = new UltraDynamicValue_SwitchComponent(    this._data, this, UltraDynamicValueTypes.NUMBER); break; }
			case 3: { this._component = new UltraDynamicValue_VariableComponent(  this._data, this, UltraDynamicValueTypes.NUMBER); break; }
			case 4: { this._component = new UltraDynamicValue_ActorComponent(     this._data, this, UltraDynamicValueTypes.NUMBER); break; }
			case 5: { this._component = new UltraDynamicValue_EnemyComponent(     this._data, this, UltraDynamicValueTypes.NUMBER); break; }
			case 6: { this._component = new UltraDynamicValue_InventoryComponent( this._data, this, UltraDynamicValueTypes.NUMBER); break; }
			case 7: { this._component = new UltraDynamicValue_CodeComponent(      this._data, this, UltraDynamicValueTypes.NUMBER); break; }
		}
	}

	createUpdateComponent() {
		if(this._component != null) {
			this._updateComponent = this._component.getUpdateComponent();
		}
	}

	setNumber(val) {
		if(this.currentNumber !== val) {
			this.currentNumber = val;
			this.onChange.trigger(this.currentNumber);
		}
	}

	update() {
		if(this._updateComponent !== null) {
			this._updateComponent.update();
		}
	}

	destroy() {
		if(this._component !== null) {
			this._component.destroy();
		}
	}

	getConfig() {
		return this._config;
	}
}

//=============================================================================
// * UltraDynamicActorID
// *
// * Dynamically updates number representing an Actor ID based on provided data.
//=============================================================================
class UltraDynamicActorID {
	constructor() {
		this.initialize(...arguments);
	}

	initialize(textData, config) {
		this.createPublicFields();
		this.createPrivateFields(textData, config);
	}

	createPublicFields() {
		this.onChange = new UltraSignal();
		this.currentID = null;
	}

	createPrivateFields(actorIDData, config) {
		this._data = actorIDData;
		this._config = config;
		this._type = this._data.Type;
		this._component = null;
		this._updateComponent = null;
	}

	start() {
		this.createComponent();
		this.createUpdateComponent();
	}

	createComponent() {
		switch(this._type) {
			case 0: { this._component = new UltraDynamicValue_StaticComponent(    this._data, this, UltraDynamicValueTypes.ACTORID); break; }
			case 1: { this._component = new UltraDynamicValue_ActorIDComponent(   this._data, this, UltraDynamicValueTypes.ACTORID); break; }
			case 2: { this._component = new UltraDynamicValue_VariableComponent(  this._data, this, UltraDynamicValueTypes.NUMBER); break; }
			case 3: { this._component = new UltraDynamicValue_CodeComponent(      this._data, this, UltraDynamicValueTypes.NUMBER); break; }
		}
	}

	createUpdateComponent() {
		if(this._component != null) {
			this._updateComponent = this._component.getUpdateComponent();
		}
	}

	setNumber(val) {
		if(this.currentID !== val) {
			this.currentID = val;
			this.onChange.trigger(this.currentID);
		}
	}

	update() {
		if(this._updateComponent !== null) {
			this._updateComponent.update();
		}
	}

	destroy() {
		if(this._component !== null) {
			this._component.destroy();
		}
	}

	getConfig() {
		return this._config;
	}
}

//=============================================================================
// * UltraDynamicValue_BaseComponent
//=============================================================================
class UltraDynamicValue_BaseComponent {
	constructor() {
		this.initialize(...arguments);
	}

	initialize(conditionData, dynamicText, valueType) {
		this._data = conditionData;
		this._parent = dynamicText;
		this._valueType = valueType;
		this.createFields();
		if(this.verify()) {
			this.start();
		}
	}

	isText() {
		return this._valueType === UltraDynamicValueTypes.TEXT;
	}

	isNumber() {
		return this._valueType === UltraDynamicValueTypes.NUMBER;
	}

	isActorID() {
		return this._valueType === UltraDynamicValueTypes.ACTORID;
	}

	createFields() {
	}

	verify() {
		return false;
	}

	start() {
	}

	checkForChange() {
	}

	getUpdateComponent() {
		return null;
	}

	update() {
	}

	destroy() {
	}
}

//=============================================================================
// * UltraDynamicValue_StaticComponent
//=============================================================================
class UltraDynamicValue_StaticComponent extends UltraDynamicValue_BaseComponent {
	createFields() {
		if(this.isText()) {
			this._text = this._parent.getConfig().processDynamicInput(this._data.Text || "", false);
		} else if(this.isNumber()) {
			this._number = this._parent.getConfig().processDynamicInput(this._data.Number || 0, true);
		} else if(this.isActorID()) {
			this._number = this._parent.getConfig().processDynamicInput(this._data.ID || 0, true);
		}
	}

	verify() {
		if(this.isText()) {
			return this._text !== "";
		} else if(this.isNumber()) {
			return this._number !== null;
		} else if(this.isActorID()) {
			return this._number !== null;
		}
		return false;
	}

	start() {
		this.checkForChange();
	}

	checkForChange() {
		if(this.isText()) {
			this._parent.setText(this._text);
		} else if(this.isNumber()) {
			this._parent.setNumber(this._number);
		} else if(this.isActorID()) {
			this._parent.setNumber(this._number);
		}
	}
}

//=============================================================================
// * UltraDynamicValue_GeneralComponent
//=============================================================================
class UltraDynamicValue_GeneralComponent extends UltraDynamicValue_BaseComponent {
	createFields() {
		this._generalType = this._data.Info || 0;
		this._destroyId = null;
	}

	verify() {
		return typeof this._generalType === "number";
	}

	start() {
		this.checkForChange();
		switch(this._generalType) {
			case 0:
			case 1:
			case 2:
			case 3:
			case 8: {
				this._destroyId = UltraTriggerManager.onMapChanged.run(this.checkForChange.bind(this));
				break;
			}
			case 101: {
				this._destroyId = UltraTriggerManager.onGoldChanged.run(this.checkForChange.bind(this));
				break;
			}
			case 203:
			case 204:
			case 205:
			case 206: {
				this._destroyId = UltraTriggerManager.onSystemStatsChanged.run(this.checkForChange.bind(this));
				break;
			}
		}
	}

	initCheckForChange() {
		if(this.isText()) {
			this._resultText = null;
			this._resultNumber = null;
		} else if(this.isNumber()) {
			this._resultNumber = null;
		}
	}

	processCheckForChange() {
		switch(this._generalType) {
			case 0: { this._resultNumber = $gameMap.mapId(); break; }
			case 1: { this._resultText = $gameMap.displayName(); break; }
			case 2: { this._resultNumber = $gameMap.width(); break; }
			case 3: { this._resultNumber = $gameMap.height(); break; }
			case 4: { this._resultNumber = Graphics.width; break; }
			case 5: { this._resultNumber = Graphics.height; break; }
			case 6: { this._resultNumber = window.innerWidth; break; }
			case 7: { this._resultNumber = window.innerHeight; break; }
			case 8: {
				const id = $gameMap.mapId();
				if($dataMapInfos && $dataMapInfos[id]) {
					this._resultText = $dataMapInfos[id].name || "";
				}
				break;
			}
			case 100: { this._resultNumber = $gameParty.size(); break; }
			case 101: { this._resultNumber = $gameParty.gold(); break; }
			case 102: { this._resultNumber = $gamePlayer.x; break; }
			case 103: { this._resultNumber = $gamePlayer.y; break; }
			case 104: {
				if(this.isText()) {
					this._resultText = UltraUtils.convertDirectionToText($gamePlayer.direction());
				} else {
					this._resultNumber = $gamePlayer.direction();
				}
				break;
			}
			case 105: { this._resultNumber = !!$dataMap ? $gamePlayer.screenX() : 0; break; }
			case 106: { this._resultNumber = !!$dataMap ? $gamePlayer.screenY() : 0; break; }
			case 200: { this._resultNumber = $gameParty.steps(); break; }
			case 201: { this._resultNumber = $gameSystem.playtimeText(); break; }
			case 202: { this._resultNumber = $gameTimer.seconds(); break; }
			case 203: { this._resultNumber = $gameSystem.saveCount(); break; }
			case 204: { this._resultNumber = $gameSystem.battleCount(); break; }
			case 205: { this._resultNumber = $gameSystem.winCount(); break; }
			case 206: { this._resultNumber = $gameSystem.escapeCount(); break; }
		}
	}

	saveCheckForChange() {
		if(this.isText()) {
			if(this._resultText !== null) {
				this._parent.setText(this._resultText);
			} else if(this._resultNumber !== null) {
				this._parent.setText(this._resultNumber.toString());
			}
		} else if(this.isNumber()) {
			if(this._resultNumber !== null) {
				this._parent.setNumber(this._resultNumber);
			}
		}
	}

	checkForChange() {
		this.initCheckForChange();
		this.processCheckForChange();
		this.saveCheckForChange();
	}

	getUpdateComponent() {
		switch(this._generalType) {
			case 6:
			case 7:
			case 100:
			case 102:
			case 103:
			case 104:
			case 105:
			case 106:
			case 200:
			case 201:
			case 202: return this;
		}
		return null;
	}

	update() {
		this.checkForChange();
	}

	destroy() {
		if(this._destroyId !== null) {
			switch(this._generalType) {
				case 0:
				case 1:
				case 2:
				case 3: {
					UltraTriggerManager.onMapChanged.remove(this._destroyId);
					break;
				}
				case 101: {
					UltraTriggerManager.onGoldChanged.remove(this._destroyId);
					break;
				}
				case 203:
				case 204:
				case 205:
				case 206: {
					UltraTriggerManager.onSystemStatsChanged.remove(this._destroyId);
					break;
				}
			}
		}
	}
}

//=============================================================================
// * UltraDynamicValue_SwitchComponent
//=============================================================================
class UltraDynamicValue_SwitchComponent extends UltraDynamicValue_BaseComponent {
	createFields() {
		this._id = this._data.ID;
		this._destroyId = null;
		if(this.isText()) {
			this._offText = this._parent.getConfig().processDynamicInput(this._data.OffText || "", false);
			this._onText = this._parent.getConfig().processDynamicInput(this._data.OnText || "", false);
		} else if(this.isNumber()) {
			this._offNum = this._parent.getConfig().processDynamicInput(this._data.OffNum || 0, true);
			this._onNum = this._parent.getConfig().processDynamicInput(this._data.OnNum || 0, true);
		}
	}

	verify() {
		return this._id >= 1 && this._id < $dataSystem.switches.length;
	}

	start() {
		this.checkForChange();
		this._destroyId = UltraTriggerManager.onSwitchChanged.run(this.checkForChange.bind(this));
	}

	checkForChange() {
		const switchVal = $gameSwitches.value(this._id);
		if(this.isText()) {
			this._parent.setText(switchVal ? this._onText : this._offText);
		} else if(this.isNumber()) {
			this._parent.setNumber(switchVal ? this._offNum : this._onNum);
		}
	}

	destroy() {
		if(this._destroyId !== null) {
			UltraTriggerManager.onSwitchChanged.remove(this._destroyId);
		}
	}
}

//=============================================================================
// * UltraDynamicValue_VariableComponent
//=============================================================================
class UltraDynamicValue_VariableComponent extends UltraDynamicValue_BaseComponent {
	createFields() {
		this._id = this._data.ID;
		this._destroyId = null;
	}

	verify() {
		return this._id >= 1 && this._id < $dataSystem.variables.length;
	}

	start() {
		this.checkForChange();
		this._destroyId = UltraTriggerManager.onVariableChanged.run(this.checkForChange.bind(this));
	}

	checkForChange() {
		const variableVal = $gameVariables.value(this._id);
		if(this.isText()) {
			this._parent.setText(variableVal.toString());
		} else if(this.isNumber()) {
			this._parent.setNumber(variableVal);
		}
	}

	destroy() {
		if(this._destroyId !== null) {
			UltraTriggerManager.onVariableChanged.remove(this._destroyId);
		}
	}
}

//=============================================================================
// * UltraDynamicValue_ActorComponent
//=============================================================================
class UltraDynamicValue_ActorComponent extends UltraDynamicValue_BaseComponent {
	createFields() {
		this._actorType = this._data.ActorType;
		this._actorIndex = this._actorType ? this._data.ID : this._parent.getConfig().processDynamicInput(this._data.Index || 0, true);
		this._info = this._data.Info || 0;
	}

	verify() {
		return this._actorIndex >= 1;
	}

	start() {
		this.checkForChange();
	}

	getActor() {
		return UltraUtils.getActor(this._actorType, this._actorIndex);
	}

	initCheckForChange() {
		if(this.isText()) {
			this._resultText = null;
			this._resultNumber = null;
		} else if(this.isNumber()) {
			this._resultNumber = null;
		}
	}

	processCheckForChange() {
		const actor = this.getActor();
		if(actor !== null) {
			switch(this._info) {
				case 0: { this._resultText = actor.name(); break }
				case 1: { this._resultNumber = actor.level; break }
				case 2: { this._resultNumber = actor.currentExp(); break }
				case 3: { this._resultNumber = actor.hp; break }
				case 4: { this._resultNumber = actor.mp; break }
				case 5: { this._resultNumber = actor.tp; break }
				case 6: { this._resultNumber = actor.tpbChargeTime(); break }
				case 7: { this._resultNumber = 1; break }
				case 8: { this._resultNumber = actor.mhp; break }
				case 9: { this._resultNumber = actor.mmp; break }
				case 10: { this._resultNumber = actor.maxTp(); break }
				case 11: { this._resultNumber = actor.atk; break }
				case 12: { this._resultNumber = actor.def; break }
				case 13: { this._resultNumber = actor.mat; break }
				case 14: { this._resultNumber = actor.mdf; break }
				case 15: { this._resultNumber = actor.agi; break }
				case 16: { this._resultNumber = actor.luk; break }
			}
		}
	}

	saveCheckForChange() {
		if(this.isText()) {
			if(this._resultText !== null) {
				this._parent.setText(this._resultText);
			} else if(this._resultNumber !== null) {
				this._parent.setText(this._resultNumber.toString());
			}
		} else if(this.isNumber()) {
			if(this._resultNumber !== null) {
				this._parent.setNumber(this._resultNumber);
			}
		}
	}

	checkForChange() {
		this.initCheckForChange();
		this.processCheckForChange();
		this.saveCheckForChange();
	}

	getUpdateComponent() {
		return this;
	}

	update() {
		this.checkForChange();
	}
}

//=============================================================================
// * UltraDynamicValue_EnemyComponent
//=============================================================================
class UltraDynamicValue_EnemyComponent extends UltraDynamicValue_BaseComponent {
	createFields() {
		this._enemyType = this._data.EnemyType;
		this._enemyIndex = this._enemyType ? this._data.ID : this._parent.getConfig().processDynamicInput(this._data.Index || 0, true);
		this._info = this._data.Info || 0;
	}

	verify() {
		return this._enemyIndex >= 1;
	}

	start() {
		this.checkForChange();
	}

	getEnemy() {
		return UltraUtils.getEnemy(this._enemyType, this._enemyIndex);
	}

	initCheckForChange() {
		if(this.isText()) {
			this._resultText = null;
			this._resultNumber = null;
		} else if(this.isNumber()) {
			this._resultNumber = null;
		}
	}

	processCheckForChange() {
		const actor = this.getEnemy();
		if(actor !== null) {
			switch(this._info) {
				case 0: { this._resultText = actor.name(); break }
				case 1: { this._resultNumber = actor.hp; break }
				case 2: { this._resultNumber = actor.mp; break }
				case 3: { this._resultNumber = actor.tp; break }
				case 4: { this._resultNumber = actor.tpbChargeTime(); break }
				case 5: { this._resultNumber = 1; break }
				case 6: { this._resultNumber = actor.mhp; break }
				case 7: { this._resultNumber = actor.mmp; break }
				case 8: { this._resultNumber = actor.maxTp(); break }
				case 9: { this._resultNumber = actor.atk; break }
				case 10: { this._resultNumber = actor.def; break }
				case 11: { this._resultNumber = actor.mat; break }
				case 12: { this._resultNumber = actor.mdf; break }
				case 13: { this._resultNumber = actor.agi; break }
				case 14: { this._resultNumber = actor.luk; break }
			}
		}
	}

	saveCheckForChange() {
		if(this.isText()) {
			if(this._resultText !== null) {
				this._parent.setText(this._resultText);
			} else if(this._resultNumber !== null) {
				this._parent.setText(this._resultNumber.toString());
			}
		} else if(this.isNumber()) {
			if(this._resultNumber !== null) {
				this._parent.setNumber(this._resultNumber);
			}
		}
	}

	checkForChange() {
		this.initCheckForChange();
		this.processCheckForChange();
		this.saveCheckForChange();
	}

	getUpdateComponent() {
		return this;
	}

	update() {
		this.checkForChange();
	}
}

//=============================================================================
// * UltraDynamicValue_InventoryComponent
//=============================================================================
class UltraDynamicValue_InventoryComponent extends UltraDynamicValue_BaseComponent {
	createFields() {
		this._itemType = this._data.ItemType;
		this._id = this._data.ID;
		this._destroyId = null;
	}

	verify() {
		switch(this._itemType) {
			case 0: return this._id >= 1 && this._id < $dataItems.length;
			case 1: return this._id >= 1 && this._id < $dataWeapons.length;
			case 2: return this._id >= 1 && this._id < $dataArmors.length;
		}
		return false;
	}

	start() {
		switch(this._itemType) {
			case 0: { this.checkForChange = this.checkItems; break; }
			case 1: { this.checkForChange = this.checkWeapons; break; }
			case 2: { this.checkForChange = this.checkArmors; break; }
		}
		this.checkForChange();
		this._destroyId = UltraTriggerManager.onItemCountChanged.run(this.checkForChange.bind(this));
	}

	checkItems() {
		const itemCount = $gameParty.numItems($dataItems[this._id]);
		if(this.isText()) {
			this._parent.setText(itemCount.toString());
		} else if(this.isNumber()) {
			this._parent.setNumber(itemCount);
		}
	}

	checkWeapons() {
		const weaponCount = $gameParty.numItems($dataWeapons[this._id]);
		if(this.isText()) {
			this._parent.setText(weaponCount.toString());
		} else if(this.isNumber()) {
			this._parent.setNumber(weaponCount);
		}
	}

	checkArmors() {
		const armorCount = $gameParty.numItems($dataArmors[this._id]);
		if(this.isText()) {
			this._parent.setText(armorCount.toString());
		} else if(this.isNumber()) {
			this._parent.setNumber(armorCount);
		}
	}

	destroy() {
		if(this._destroyId !== null) {
			UltraTriggerManager.onItemCountChanged.remove(this._destroyId);
			this._destroyId = null;
		}
	}
}

//=============================================================================
// * UltraDynamicValue_CodeComponent
//=============================================================================
class UltraDynamicValue_CodeComponent extends UltraDynamicValue_BaseComponent {
	createFields() {
		this._func = this._parent.getConfig().createCustomFunction(this._data.Code, null, this);
	}

	verify() {
		return this._func !== null;
	}

	start() {
		this.checkForChange();
	}

	checkForChange() {
		if(this._func !== null) {
			if(this.isText()) {
				this._parent.setText(this._func() || "");
			} else if(this.isNumber()) {
				this._parent.setNumber(this._func() || 0);
			}
		}
	}

	getUpdateComponent() {
		return this;
	}

	update() {
		this.checkForChange();
	}
}

//=============================================================================
// * UltraDynamicValue_ActorIDComponent
//=============================================================================
class UltraDynamicValue_ActorIDComponent extends UltraDynamicValue_BaseComponent {
	createFields() {
		this._actorIndex = this._parent.getConfig().processDynamicInput(this._data.Index || 0, true);
	}

	verify() {
		return this._actorIndex >= 1;
	}

	start() {
		this.checkForChange();
	}

	getActor() {
		return UltraUtils.getActor(false, this._actorIndex);
	}

	checkForChange() {
		let result = null;
		const actor = this.getActor();
		if(actor !== null) {
			result = actor.actorId();
		}
		this._parent.setNumber(result);
	}

	getUpdateComponent() {
		return this;
	}

	update() {
		this.checkForChange();
	}
}

//=============================================================================
// * Bitmap
// *
// * Adds `fillRectOutline` and `fillEllipse` to Bitmap.
//=============================================================================
Bitmap.prototype.fillRectOutline = function(x, y, width, height, size, color) {
	if(width <= 0 || height <= 0) {
		return;
	}
	const context = this.context;
	context.save();
	context.fillStyle = color;
	context.fillRect(x, y, width, size); // top
	context.fillRect(x, y + height - size, width, size); // bottom
	context.fillRect(x, y + size, size, height - (size * 2)); // left
	context.fillRect(x + width - size, y + size, size, height - (size * 2)); // right
	context.restore();
	this._baseTexture.update();
};

Bitmap.prototype.fillEllipse = function(x, y, width, height, color) {
	if(width <= 0 || height <= 0) {
		return;
	}
	const halfWidth = width / 2;
	const halfHeight = height / 2;
	const context = this.context;
	context.save();
	context.fillStyle = color;
	context.beginPath();
	context.ellipse(halfWidth + x, halfHeight + y, halfWidth, halfHeight, 0, 0, Math.PI * 2);
	context.fill();
	context.restore();
	this._baseTexture.update();
};

//=============================================================================
// * Sprite
// *
// * Adds `brightness` input for the color filter.
// * Why this doesn't exist already? Who knows...
//=============================================================================
$.Sprite = $.Sprite || {};

$.Sprite.initialize = Sprite.prototype.initialize;
Sprite.prototype.initialize = function(bitmap) {
	$.Sprite.initialize.apply(this, arguments);
	this._filterBrightness = 255;
};

Sprite.prototype.getBrightness = function() {
	return this._filterBrightness;
};

Sprite.prototype.setBrightness = function(brightness) {
	if(this._filterBrightness !== brightness) {
		this._filterBrightness = brightness;
		this._updateColorFilter();
	}
};

$.Sprite._updateColorFilter = Sprite.prototype._updateColorFilter;
Sprite.prototype._updateColorFilter = function() {
	$.Sprite._updateColorFilter.apply(this, arguments);
	this._colorFilter.setBrightness(this._filterBrightness);
};

//=============================================================================
// * DataManager
// *
// * Added alternative functions for loading data files from `data/plugin/`.
// *
// * Placing custom data files on top level of `data` folder causes MZ
// * to prompt whenever they are modified while the MZ editor is open.
// * Placing them in child folder fixes this problem.
// *
// * Unfortunately, that means you have to copy/paste a lot of DataManager
// * loading since the normal path is hardcoded. >.<
// *
// * If you're a plugin dev that wishes to use a custom data file,
// * please consider also using the "plugin" folder in the "data" folder for
// * consistency and user convenience.
// *
// * Used "_Ultra" suffix on new functions to prevent conflicts with plugins
// * that may do something similar.
//=============================================================================
$.DataManager = $.DataManager || {};

$.DataManager.loadDatabase = DataManager.loadDatabase;
DataManager.loadDatabase = function() {
	$.DataManager.loadDatabase.apply(this, arguments);
	this.loadPluginDatabase_Ultra();
};

DataManager.loadPluginDatabase_Ultra = function() {
	if(this._databasePluginFiles_Ultra) {
		for(const databasePluginFile of this._databasePluginFiles_Ultra) {
			this.loadPluginDataFile_Ultra(databasePluginFile.name, databasePluginFile.src);
		}
	}
};

DataManager.pluginDatabasePath_Ultra = function() {
	return "data/plugin/";
}

DataManager.loadPluginDataFile_Ultra = function(name, src) {
	const xhr = new XMLHttpRequest();
	const url = this.pluginDatabasePath_Ultra() + src;
	window[name] = null;
	xhr.open("GET", url);
	xhr.overrideMimeType("application/json");
	xhr.onload = () => this.onXhrLoad(xhr, name, src, url);
	xhr.onerror = () => this.onXhrError(name, src, url);
	xhr.send();
};

$.DataManager.isDatabaseLoaded = DataManager.isDatabaseLoaded;
DataManager.isDatabaseLoaded = function() {
	if(!$.DataManager.isDatabaseLoaded.apply(this, arguments)) return false;
	return this.isPluginDatabaseLoaded_Ultra();
};

DataManager.isPluginDatabaseLoaded_Ultra = function() {
	if(this._databasePluginFiles_Ultra) {
		for(const databaseFile of this._databasePluginFiles_Ultra) {
			if(!window[databaseFile.name]) {
				return false;
			}
		}
	}
	return true;
};

//=============================================================================
// * UltraTriggerManager
// *
// * Stores references to various triggers.
//=============================================================================
class UltraTriggerManager {
	static initialize() {
		this.onSwitchChanged = new UltraSignal();
		this.onVariableChanged = new UltraSignal();
		this.onGoldChanged = new UltraSignal();
		this.onItemCountChanged = new UltraSignal();
		this.onMapChanged = new UltraSignal();
		this.onSystemStatsChanged = new UltraSignal();
	}

	static onSwitchChange() {
		this.onSwitchChanged.trigger();
	}

	static onVariableChange() {
		this.onVariableChanged.trigger();
	}

	static onGoldChange() {
		this.onGoldChanged.trigger();
	}

	static onItemCountChange() {
		this.onItemCountChanged.trigger();
	}

	static onMapChange() {
		this.onMapChanged.trigger();
	}

	static onSystemStatsChange() {
		this.onSystemStatsChanged.trigger();
	}

	static onFaceImageChange(actorId) {
		const signal = UltraTriggerManager.getOnFaceChangeSignal(actorId);
		if(signal) {
			signal.trigger();
		}
	}

	static getOnFaceChangeSignal(actorId) {
		if(!this.onFaceImageChangeArray) {
			this.onFaceImageChangeArray = [];
		}
		if(!this.onFaceImageChangeArray[actorId]) {
			this.onFaceImageChangeArray[actorId] = new UltraSignal();
		}
		return this.onFaceImageChangeArray[actorId];
	}
}

UltraTriggerManager.initialize();

//=============================================================================
// * Game_Switches
// *
// * Added an `UltraSignal` that triggers whenever a switch is changed.
//=============================================================================
$.Game_Switches_onChange = Game_Switches.prototype.onChange;
Game_Switches.prototype.onChange = function() {
	$.Game_Switches_onChange.apply(this, arguments);
	UltraTriggerManager.onSwitchChange();
};

//=============================================================================
// * Game_Switches
// *
// * Added an `UltraSignal` that triggers whenever a variable is changed.
//=============================================================================
$.Game_Variables_onChange = Game_Variables.prototype.onChange;
Game_Variables.prototype.onChange = function() {
	$.Game_Variables_onChange.apply(this, arguments);
	UltraTriggerManager.onVariableChange();
};

//=============================================================================
// * Game_Party
// *
// * Added an `UltraSignal` that triggers whenever a gold is changed.
//=============================================================================
$.Game_Party_gainGold = Game_Party.prototype.gainGold;
Game_Party.prototype.gainGold = function(amount) {
	$.Game_Party_gainGold.apply(this, arguments);
	UltraTriggerManager.onGoldChange();
};

$.Game_Party_gainItem = Game_Party.prototype.gainItem;
Game_Party.prototype.gainItem = function(item, amount, includeEquip) {
	$.Game_Party_gainItem.apply(this, arguments);
	UltraTriggerManager.onItemCountChange();
};

//=============================================================================
// * Game_Map
// *
// * Added an `UltraSignal` that triggers whenever map is changed.
//=============================================================================
$.Game_Map_setup = Game_Map.prototype.setup;
Game_Map.prototype.setup = function(mapId) {
	$.Game_Map_setup.apply(this, arguments);
	UltraTriggerManager.onMapChange();
};

//=============================================================================
// * Game_System
// *
// * Added an `UltraSignal` that triggers whenever map is changed.
//=============================================================================
$.Game_System_onBattleStart = Game_System.prototype.onBattleStart;
Game_System.prototype.onBattleStart = function() {
	$.Game_System_onBattleStart.apply(this, arguments);
	UltraTriggerManager.onSystemStatsChange();
};

$.Game_System_onBattleWin = Game_System.prototype.onBattleWin;
Game_System.prototype.onBattleWin = function() {
	$.Game_System_onBattleWin.apply(this, arguments);
	UltraTriggerManager.onSystemStatsChange();
};

$.Game_System_onBattleEscape = Game_System.prototype.onBattleEscape;
Game_System.prototype.onBattleEscape = function() {
	$.Game_System_onBattleEscape.apply(this, arguments);
	UltraTriggerManager.onSystemStatsChange();
};

$.Game_System_onBeforeSave = Game_System.prototype.onBeforeSave;
Game_System.prototype.onBeforeSave = function() {
	$.Game_System_onBeforeSave.apply(this, arguments);
	UltraTriggerManager.onSystemStatsChange();
};

//=============================================================================
// * Game_Actor
// *
// * Added an `UltraSignal` that triggers whenever actor face image is changed.
//=============================================================================
$.Game_Actor_setFaceImage = Game_Actor.prototype.setFaceImage;
Game_Actor.prototype.setFaceImage = function(faceName, faceIndex) {
	$.Game_Actor_setFaceImage.apply(this, arguments);
	UltraTriggerManager.onFaceImageChange(this._actorId);
};

Game_Actor.prototype.getOnFaceChangeSignal = function() {
	return UltraTriggerManager.getOnFaceChangeSignal(this._actorId);
};

//=============================================================================
// * Plugin Exports
//=============================================================================
const exports = window;
exports.UltraTriggerManager                             = UltraTriggerManager;
exports.UltraSignal                                     = UltraSignal;
exports.UltraUtils                                      = UltraUtils;
exports.UltraEasingCurveTypes                           = UltraEasingCurveTypes;
exports.UltraEasingCurve                                = UltraEasingCurve;
exports.UltraProcessConfiguration                       = UltraProcessConfiguration;
exports.UltraDynamicCondition                           = UltraDynamicCondition;
exports.UltraDynamicMultiCondition                      = UltraDynamicMultiCondition;
exports.UltraDynamicCondition_BaseComponent             = UltraDynamicCondition_BaseComponent;
exports.UltraDynamicCondition_SwitchComponent           = UltraDynamicCondition_SwitchComponent;
exports.UltraDynamicCondition_VariableComponent         = UltraDynamicCondition_VariableComponent;
exports.UltraDynamicCondition_ActorComponent            = UltraDynamicCondition_ActorComponent;
exports.UltraDynamicCondition_EnemyComponent            = UltraDynamicCondition_EnemyComponent;
exports.UltraDynamicCondition_PlayerDirectionComponent  = UltraDynamicCondition_PlayerDirectionComponent;
exports.UltraDynamicCondition_GoldComponent             = UltraDynamicCondition_GoldComponent;
exports.UltraDynamicCondition_ButtonComponent           = UltraDynamicCondition_ButtonComponent;
exports.UltraDynamicCondition_InventoryComponent        = UltraDynamicCondition_InventoryComponent;
exports.UltraDynamicCondition_OtherComponent            = UltraDynamicCondition_OtherComponent;
exports.UltraDynamicCondition_CodeComponent             = UltraDynamicCondition_CodeComponent;
exports.UltraDynamicValueTypes                          = UltraDynamicValueTypes;
exports.UltraDynamicText                                = UltraDynamicText;
exports.UltraDynamicNumber                              = UltraDynamicNumber;
exports.UltraDynamicActorID                             = UltraDynamicActorID;
exports.UltraDynamicValue_BaseComponent                 = UltraDynamicValue_BaseComponent;
exports.UltraDynamicValue_StaticComponent               = UltraDynamicValue_StaticComponent;
exports.UltraDynamicValue_GeneralComponent              = UltraDynamicValue_GeneralComponent;
exports.UltraDynamicValue_SwitchComponent               = UltraDynamicValue_SwitchComponent;
exports.UltraDynamicValue_VariableComponent             = UltraDynamicValue_VariableComponent;
exports.UltraDynamicValue_ActorComponent                = UltraDynamicValue_ActorComponent;
exports.UltraDynamicValue_EnemyComponent                = UltraDynamicValue_EnemyComponent;
exports.UltraDynamicValue_InventoryComponent            = UltraDynamicValue_InventoryComponent;
exports.UltraDynamicValue_CodeComponent                 = UltraDynamicValue_CodeComponent;
exports.UltraDynamicValue_ActorIDComponent              = UltraDynamicValue_ActorIDComponent;

})(SRD.UltraBase);
