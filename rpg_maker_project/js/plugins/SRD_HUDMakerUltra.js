/*:
 * @target MZ
 * @plugindesc Allows you to create and use HUDs for the map and battles.
 * Requires the HUD Maker Ultra editor.
 * @author SRDude
 * @url http://sumrndm.site/hud-maker-ultra
 * @base SRD_UltraBase
 * @orderAfter SRD_UltraBase
 * @orderBefore SRD_HUDMakerUltraPro
 *
 * @param Auto-Reload HUD Data
 * @desc If ON, everytime the game window receives focus, the editor data will be reloaded. Only works during play-tests.
 * @type boolean
 * @default false
 *
 * @param Enable Screenshots
 * @desc If ON, pressing "CTRL + S" will take a screen-shot of the game without the HUD.
 * @type boolean
 * @default false
 *
 * @param Hide Battle Status Window
 * @desc If ON, the party's battle status window will be made invisible.
 * @type boolean
 * @on Hide
 * @off Show
 * @default false
 *
 * @param Hide Battle Selection Window
 * @desc If ON, the enemy/party selection window will be made invisible.
 * @type boolean
 * @on Hide
 * @off Show
 * @default false
 *
 * @param Fade During Events
 * @desc If ON, the HUD will fade out during events.
 * @type boolean
 * @default true
 *
 * @param Event Fade Opacity
 * @desc The opacity of the HUD during event processing.
 * Select a number between 0 and 255.
 * @type number
 * @default 125
 *
 * @param Fade Duration
 * @desc The duration of the fade animation upon changing between visibility modes.
 * @type number
 * @default 10
 *
 * @param Map Visibility Code
 * @desc Code that dictates the HUD's visibility on the map.
 * Leave as "return true;" to not affect the HUD.
 * @type multiline_string
 * @default return true;
 *
 * @param Battle Visibility Code
 * @desc Code that dictates the HUD's visibility in battle.
 * Leave as "return true;" to not affect the HUD.
 * @type multiline_string
 * @default return true;
 *
 * @command Set HUD Visibility
 * @text Set HUD Visibility
 * @desc Sets the HUD to visible or invisible.
 *
 * @arg Visible?
 * @desc Whether the HUD is set to visible or invisible.
 * @type boolean
 * @on Visible
 * @off Invisible
 * @default true
 *
 * @command Set HUD Activity
 * @text Set HUD Activity
 * @desc Sets the HUD to be active or inactive.
 *
 * @arg Active?
 * @desc Whether the HUD is active.
 * @type boolean
 * @on Active
 * @off Inactive
 * @default true
 *
 * @help
 * ============================================================================
 *                                HUD Maker Ultra
 *                                 Version 1.1.5
 *                                    SRDude
 * ============================================================================
 *
 * This plugin allows developers to create their own map and battle HUD.
 *
 * This plugin requires the HUD Maker Ultra software.
 * You can download it for free here:
 * http://sumrndm.site/hud-maker-ultra
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
SRD.HUDMakerUltra = SRD.HUDMakerUltra || {};

var Imported = Imported || {};
Imported.SRD_HUDMakerUltra = 0x010105; // 1.1.5

var $dataUltraHUD = null;
var $gameUltraHUD = null;

(function($) {

"use strict";

//=============================================================================
// * hudDataPath
// *
// * We use this a lot, so let's store it.
//=============================================================================
$.hudDataPath = "data/plugin/UltraHUD.json";

//=============================================================================
// * CheckDependencies
//=============================================================================
function CheckDependencies() {
	if(typeof Imported.SRD_UltraBase !== "number") {
		console.warn("SRD_HUDMakerUltra.js requires SRD_UltraBase.js to be installed!");
		return false;
	}

	if(Imported.SRD_UltraBase < 0x010100) {
		const msg = "SRD_UltraBase.js requies an update! Please update to the latest version.";
		console.warn(msg);
		if(confirm(msg + "\nWould you like to open the download page (right-click -> save)?")) {
			const url = "https://raw.githubusercontent.com/SumRndmDde/HUDMakerUltra/main/SRD_UltraBase.js";
			if(Utils.isNwjs()) {
				require('nw.gui').Shell.openExternal(url);
			} else if(window && window.open) {
				window.open(url);
			}
		}
		return false;
	}

	if(!SRD.UltraBase.addDataFile("$dataUltraHUD", "UltraHUD.json")) {
		console.warn("Could not find \"" + $.hudDataPath + "\". SRD_HUDMakerUltra.js will not function.");
		return false;
	}

	return true;
}

if(!CheckDependencies()) {
	$.hadError = true;
	return;
}

//=============================================================================
// * Plugin Parameters
//=============================================================================

const params = PluginManager.parameters("SRD_HUDMakerUltra");

$.autoReload = String(params["Auto-Reload HUD Data"]).trim().toLowerCase() === "true";
$.screenshots = String(params["Enable Screenshots"]).trim().toLowerCase() === "true";
$.hideStatusWindow = String(params["Hide Battle Status Window"]).trim().toLowerCase() === "true";
$.hideSelectionWindow = String(params["Hide Battle Selection Window"]).trim().toLowerCase() === "true";
$.hideDuringEvents = String(params["Fade During Events"]).trim().toLowerCase() === "true";
$.fadeOpacity = parseInt(params["Event Fade Opacity"] || "125") / 255;
$.fadeDuration = parseInt(params["Fade Duration"] || "10");
$.mapVisibilityFunc = SRD.UltraBase.convertStringToFunc(params["Map Visibility Code"], "\"Map Visibility Code\" Error");
$.battleVisibilityFunc = SRD.UltraBase.convertStringToFunc(params["Battle Visibility Code"], "\"Battle Visibility Code\" Error");

//=============================================================================
// * UltraHUDManager
// *
// * Singleton for managing HUD Maker Ultra's HUD.
//=============================================================================
class UltraHUDManager {
	static getHUDDataString() {
		if(Utils.isNwjs()) {
			const fs = require("fs");
			if(fs.existsSync($.hudDataPath)) {
				return fs.readFileSync($.hudDataPath);
			}
		}
		return "";
	}

	static checkHUDDataString(dontReload) {
		const hudJson = this.getHUDDataString();
		if(this._hudJson !== hudJson) {
			this._hudJson = hudJson;
			if(!dontReload) {
				this.reloadHUDData();
			}
		}
	}

	static reloadHUDData() {
		if(this._hudJson && this._hudJson.length > 0) {
			let newUltraHUDData = null;
			try {
				newUltraHUDData = JSON.parse(this._hudJson);
			} catch(e) {
			}
			if(newUltraHUDData) {
				const scene = SceneManager._scene;
				if(scene && scene.refreshUltraHUD) {
					$dataUltraHUD = newUltraHUDData;
					scene.refreshUltraHUD();
				}
			}
		}
	}

	static preloadHUDMakerUltraFonts() {
		this.maximumFontId = 1;
		this.fontRegistry = {};
		if($dataUltraHUD) {
			const HUDList = $dataUltraHUD.Data;
			if(HUDList) {
				const len = HUDList.length;
				for(let i = 0; i < len; i++) {
					this.preloadHUDMakerUltraFontsFromComponentList(HUDList[i].HUD);
				}
			}
		}
	}

	static preloadHUDMakerUltraFontsFromComponentList(list) {
		if(list) {
			const len = list.length;
			for(let i = 0; i < len; i++) {
				const comp = list[i];
				this.preloadHUDMakerUltraFontsFromComponent(comp);
				if(comp && comp.Children && comp.Children.length > 0) {
					this.preloadHUDMakerUltraFontsFromComponentList(list[i].Children);
				}
			}
		}
	}

	static preloadHUDMakerUltraFontsFromComponent(comp) {
		if(comp && comp.Type === 0) {
			this.registerHUDMakerUltraFont(comp.TextData.FontFamily);
		}
	}

	static registerHUDMakerUltraFont(fontFilename) {
		if(fontFilename) {
			const fontFamily = "hudmakerultra-font" + this.maximumFontId;
			FontManager.load(fontFamily, fontFilename);
			this.fontRegistry[fontFilename] = fontFamily;
			this.maximumFontId++;
		}
	}

	static getFontFamily(fontFilename) {
		if(!fontFilename) {
			return "rmmz-mainfont";
		}
		return this.fontRegistry[fontFilename];
	}
}

//=============================================================================
// * Game_UltraHUD
// *
// * Stores changes to HUD state.
//=============================================================================

class Game_UltraHUD {
	constructor() {
		this.initialize(...arguments);
	}

	initialize() {
		this.globalVisibility = true;
		this.globalActiveness = true;
	}

	setGlobalVisibility(visible) {
		if(this.globalVisibility !== visible) {
			this.globalVisibility = visible;
			this.updateUltraHUDContainerVisibility();
		}
	}

	setGlobalActiveness(visible) {
		if(this.globalActiveness !== visible) {
			this.globalActiveness = visible;
			this.updateUltraHUDContainerVisibility();
		}
	}

	updateUltraHUDContainerVisibility() {
		const scene = SceneManager._scene;
		if(scene && scene.updateUltraHUDContainerVisibility) {
			scene.updateUltraHUDContainerVisibility();
		}
	}

	isHUDEnabled() {
		const scene = SceneManager._scene;
		if(scene && scene._ultraHudContainer) {
			return scene._ultraHudContainer.isHUDEnabled();
		}
		return true;
	}

	mapHUDID() {
		return $dataUltraHUD.Map;
	}

	battleHUDID() {
		return $dataUltraHUD.Battle;
	}

	refreshHUD() {
		const scene = SceneManager._scene;
		if(this.isValidScene()) {
			scene.refreshUltraHUD();
		}
	}

	isValidScene() {
		const scene = SceneManager._scene;
		return scene && scene.refreshUltraHUD;
	}
}

//=============================================================================
// * HUDMakerUltraProcessConfiguration
// *
// * Used to configure the behavior of dynamic processes for HUD Maker Ultra.
//=============================================================================
class HUDMakerUltraProcessConfiguration extends UltraProcessConfiguration {
	initialize() {
		super.initialize();
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
}

//=============================================================================
// * Stage_UltraHUDContainer
// *
// * Stores and manages HUDs.
// * Should be `PIXI.Container`, but figured it's better practice to
// * extend from RPG Maker core classes when possible.
//=============================================================================
class Stage_UltraHUDContainer extends Stage {
	initialize(isMap) {
		super.initialize();
		this._mainHUD = null;
		this._config = new HUDMakerUltraProcessConfiguration();
		this._isMap = isMap;

		this._fadeCurr = 0;
		this._fadeDuration = $.fadeDuration;
		this._fadeState = false;
	}

	createHUD() {
		this.createMapHUD();
	}

	createMapHUD() {
		this.destroyCurrentHUD();
		const mapId = this.hudID();
		const mapData = mapId >= 0 && mapId < $dataUltraHUD.Data.length ? $dataUltraHUD.Data[mapId] : null;
		this.createHUDSprite(mapData);
	}

	hudID() {
		return this._isMap ? $gameUltraHUD.mapHUDID() : $gameUltraHUD.battleHUDID();
	}

	createHUDSprite(mapData) {
		if(mapData !== null) {
			this._mainHUD = new Sprite_UltraHUD(mapData, this._config);
			this.addChild(this._mainHUD);
		}
	}

	destroyCurrentHUD() {
		if(this._mainHUD !== null) {
			this.removeChild(this._mainHUD);
			this._mainHUD.destroy();
			this._mainHUD = null;
		}
	}

	refreshUltraHUD() {
		this.destroyCurrentHUD();
		this.createHUD();
	}

	update() {
		this.updateMainHUD();
		this.processFade();
	}

	updateMainHUD() {
		if(this._mainHUD !== null) {
			this._mainHUD.update();
		}
	}

	processFade() {
		if(this.isFading()) {
			this.incrementFade();
			this.updateFade();
		}
	}

	incrementFade() {
		this._fadeCurr++;
	}

	updateFade() {
		const fadeRatio = this._fadeCurr / this._fadeDuration;
		this.alpha = ($.fadeOpacity + ((1 - $.fadeOpacity) * (this._fadeState ? fadeRatio : 1 - fadeRatio)));
	}

	setVisibilityState(val) {
		return this.setFadeState(val && $gameUltraHUD.globalActiveness);
	}

	setFadeState(val) {
		if(this._fadeState !== val) {
			const opacityRatio = this.alpha;
			this._fadeCurr = val ? Math.floor(opacityRatio * this._fadeDuration) : Math.floor((1 - opacityRatio) * this._fadeDuration);
			this._fadeState = val;
			this.updateFade();
			return true;
		}
		return false;
	}

	isFading() {
		return this._fadeCurr < this._fadeDuration;
	}

	isHUDEnabled() {
		return this._fadeState;
	}
}

//=============================================================================
// * Sprite_UltraHUD
//=============================================================================
class Sprite_UltraHUD extends Sprite {
	initialize(data, config) {
		super.initialize();
		this.createPrivateFields(config);
		this.createAllHUDComponents(data);
		this.onCreationComplete();
	}

	createPrivateFields(config) {
		this._components = [];
		this._config = config;
	}

	createAllHUDComponents(data) {
		const components = data.HUD;
		this.createComponents(components, this);
	}

	createComponents(components, parent, useChildCallback) {
		const len = components.length;
		for(let i = 0; i < len; i++) {
			const compData = components[i];
			const component = this.createHUDComponent(compData);
			if(component !== null) {
				this._components.push(component);
				parent.addChild(component);
				if(useChildCallback) {
					parent.onChildAdded(component);
				}
				if(compData.Children && compData.Children.length > 0) {
					this.createComponents(compData.Children, component, true);
				}
			}
		}
	}

	createHUDComponent(data) {
		let result = null;
		switch(data.Type) {
			case 0: { result = new Sprite_UltraHUDComponent_Text(data, this); break; }
			case 1: { result = new Sprite_UltraHUDComponent_Shape(data, this); break; }
			case 2: { result = new Sprite_UltraHUDComponent_Picture(data, this); break; }
			case 3: { result = new Sprite_UltraHUDComponent_Repeat(data, this); break; }
			case 4: { result = new Sprite_UltraHUDComponent_Gauge(data, this); break; }
			case 5: { result = new Sprite_UltraHUDComponent_PictureGauge(data, this); break; }
			case 6: { result = new Sprite_UltraHUDComponent_Group(data, this); break; }
			case 7: { result = new Sprite_UltraHUDComponent_Window(data, this); break; }
			case 8: { result = new Sprite_UltraHUDComponent_ActorFace(data, this); break; }
			case 9: { result = new Sprite_UltraHUDComponent_IconSet(data, this); break; }
		}
		return result;
	}

	onCreationComplete() {
		const len = this._components.length;
		for(let i = 0; i < len; i++) {
			this._components[i].onCreationComplete();
		}
	}

	getConfig() {
		return this._config;
	}

	findComponentByName(name) {
		const len = this._components.length;
		for(let i = 0; i < len; i++) {
			const comp = this._components[i];
			if(comp.name() === name) {
				return comp;
			}
		}
		return null;
	}

	update() {
		const len = this._components.length;
		for(let i = 0; i < len; i++) {
			this._components[i].update();
		}
	}

	destroy() {
		super.destroy();
	}
}

//=============================================================================
// * Sprite_UltraHUDComponent
//=============================================================================
class Sprite_UltraHUDComponent extends Sprite {
	initialize(data, hud) {
		super.initialize();
		this.createPrivateFields(data, hud);
		this.setupPreliminaryProperties();
		this.setupBasicProperties();
		this.setupDisplayConditions();
		this.setupAnimations();
		this.setupNotetags(data.Note);
	}

	createPrivateFields(data, hud) {
		this._data = data;
		this._hud = hud;
		this._multiCondition = null;
		this._animations = null;
		this._forcedVisibility = true;
	}

	setupPreliminaryProperties() {
		this.anchor.set(0.5);
	}

	setupBasicProperties() {
		this.x = this._data.X;
		this.y = this._data.Y;
		if(this._data.ScaleX !== undefined) {
			this.scale.x = this._data.ScaleX || 1;
		}
		if(this._data.ScaleY !== undefined) {
			this.scale.y = this._data.ScaleY || 1;
		}
		if(this._data.Rotation !== undefined) {
			this.rotation = (this._data.Rotation || 0) * (Math.PI / 180);
		}
		if(this._data.Opacity !== undefined) {
			this.alpha = Number(typeof this._data.Opacity === "number" ? this._data.Opacity : 1.0).clamp(0, 1);
		}
	}

	setupDisplayConditions() {
		if(this._data.Conditions) {
			this._multiCondition = new UltraDynamicMultiCondition(this._data.Conditions, this._hud.getConfig());
			this._multiCondition.onChange.run(this.onDisplayConditionsChanged.bind(this));
			this._multiCondition.start();
		}
	}

	setupAnimations() {
		const animations = this._data.Animations;
		if(animations && animations.length > 0) {
			this._animations = [];
			const len = animations.length;
			for(let i = 0; i < len; i++) {
				const animationData = animations[i];
				const animation = new UltraHUDComponent_Animation(this, animationData);
				this.onAnimationCreated(animation, animationData);
				this._animations.push(animation);
			}
		}
	}

	onAnimationCreated(animation, animationData) {
		animation.start(true);
	}

	onCreationComplete() {
	}

	setupNotetags(note) {
	}

	resizeBitmap(width, height) {
		const oldBitmap = this.bitmap;
		if(oldBitmap) {
			oldBitmap.resize(width, height);
			this.bitmap = null;
			this.bitmap = oldBitmap;
		}
	}

	name() {
		return this._data.Name;
	}

	hasChildComponents() {
		return false;
	}

	forcedVisibility() {
		return this._forcedVisibility;
	}

	setForcedVisibility(v) {
		if(this._forcedVisibility !== v) {
			this._forcedVisibility = v;
			this.refreshComponentVisibility();
		}
	}

	onDisplayConditionsChanged(val) {
		if(!this._destroyed) {
			this.refreshComponentVisibility();
		}
	}

	refreshComponentVisibility() {
		this.visible = this._forcedVisibility && (this._multiCondition === null || this._multiCondition.state);
	}

	update() {
		this.updateMultiCondition();
		this.updateAnimations();
	}

	updateMultiCondition() {
		if(this._multiCondition !== null) {
			this._multiCondition.update(this);
		}
	}

	updateAnimations() {
		if(this._animations !== null) {
			for(let i = 0; i < this._animations.length; i++) {
				this._animations[i].update();
			}
		}
	}

	destroy() {
		super.destroy();
		if(this._multiCondition !== null) {
			this._multiCondition.destroy();
			this._multiCondition = null;
		}
	}

	boundingRect() {
		return new Rectangle(-this.anchor.x * this.width, -this.anchor.y * this.height, this.width, this.height);
	}

	isOverlayCoordinates(x, y, yOffset = 0) {
		if(!this.isEnabled()) this.updateTransform();
		const touchPos = new Point(x, y);
		const localPos = this.worldTransform.applyInverse(touchPos);
		return this.boundingRect().contains(localPos.x, localPos.y) || 
			(yOffset != 0 ? this.boundingRect().contains(localPos.x, localPos.y + yOffset) : false);
	}

	isEnabled() {
		return this.worldVisible;
	}

	onChildAdded(child) {
	}

	isTextComponent() {
		return this._data.Type === 0;
	}
}

//=============================================================================
// * UltraHUDComponent_Animation
//=============================================================================
class UltraHUDComponent_Animation {
	constructor() {
		this.initialize(...arguments);
	}

	initialize(component, animationData) {
		this.createPrivateFields(component, animationData);
		this.createPublicFields();
	}

	createPrivateFields(component, animationData) {
		this._component = component;
		this._isRunning = false;
		this._count = 0;
		this._reverse = false;
		this._duration = animationData.Duration || 60;
		this._easing = new UltraEasingCurve(animationData.EasingCurve);
		this._reverseEasing = new UltraEasingCurve(this.getReverseEasing(animationData));
		this._start = this.getStart(animationData);
		this._end = this.getEnd(animationData);
		this._difference = this._end - this._start;
		this._property = animationData.Property;
		this._type = animationData.Type;
		this._defaultReset = !!animationData.Reset;
	}

	getReverseEasing(animationData) {
		return animationData.EasingCurve;
	}

	createPublicFields() {
		this.onAnimationComplete = new UltraSignal();
	}

	start(reset) {
		this.setupStart(false, reset);
	}

	startReversed(reset) {
		this.setupStart(true, reset);
	}

	setupStart(reverse, reset) {
		reset = reset === undefined ? this._defaultReset : reset;
		if(reset) {
			this.reset();
		} else if(this._reverse !== reverse) {
			this.invertTiming();
		}
		this._isRunning = true;
		this._reverse = reverse;
		this.updateAnimation(false);
	}

	setImmediateState(state) {
		this.reset();
		this._reverse = !state;
	}

	reset() {
		this._count = 0;
	}

	invertTiming() {
		this._count = this._duration - this._count;
	}

	stop() {
		this._isRunning = false;
	}

	update() {
		if(this.shouldUpdate()) {
			this.updateAnimation(true);
		}
	}

	shouldUpdate() {
		return this._isRunning;
	}

	updateAnimation(updateCount) {
		if(this._count <= this._duration) {
			let ratio;
			if(this._reverse) {
				ratio = 1 - this._reverseEasing.getValue(this._count / this._duration);
			} else {
				ratio = this._easing.getValue(this._count / this._duration);
			}
			this.setValue(this._start + (this._difference * ratio));
			if(updateCount) {
				this._count++;
				if(this._count > this._duration) {
					this.onAnimationEnd();
				}
			}
		}
	}

	onAnimationEnd() {
		if(this._type === 0) {
			this.stop();
		} else {
			this.reset();
			if(this._type === 2) {
				this._reverse = !this._reverse;
			}
		}
		this.onAnimationComplete.trigger();
	}

	isComponentValid() {
		return !!this._component && !this._component._destroyed;
	}

	setValue(val) {
		if(!this.isComponentValid()) return;
		switch(this._property) {
			case 0: { this._component.x = val; break; }
			case 1: { this._component.y = val; break; }
			case 2: { this._component.scale.x = val; break; }
			case 3: { this._component.scale.y = val; break; }
			case 4: { this._component.setComponentWidth(val); break; }
			case 5: { this._component.setComponentHeight(val); break; }
			case 6: { this._component.rotation = val; break; }
			case 7: { this._component.alpha = val; break; }
			case 8: { this._component.setComponentOpenness(val * 255); break; }
			case 9: { this._component.setRepeatOffsetX(val); break; }
			case 10: { this._component.setRepeatOffsetY(val); break; }
			case 11: { this._component.setBrightness(val * 255); break; }
		}
	}

	getStart(animationData) {
		switch(animationData.Property) {
			case 0: return animationData.StartX;
			case 1: return animationData.StartY;
			case 2: return animationData.StartScaleWidth;
			case 3: return animationData.StartScaleHeight;
			case 4: return animationData.StartWidth;
			case 5: return animationData.StartHeight;
			case 6: return animationData.StartRotation * (Math.PI / 180);
			case 7: return animationData.StartOpacity;
			case 8: return animationData.StartOpenness;
			case 9:
			case 10: return animationData.StartOffset;
			case 11: return animationData.StartBrightness;
		}
		return 0;
	}

	getEnd(animationData) {
		switch(animationData.Property) {
			case 0: return animationData.EndX;
			case 1: return animationData.EndY;
			case 2: return animationData.EndScaleWidth;
			case 3: return animationData.EndScaleHeight;
			case 4: return animationData.EndWidth;
			case 5: return animationData.EndHeight;
			case 6: return animationData.EndRotation * (Math.PI / 180);
			case 7: return animationData.EndOpacity;
			case 8: return animationData.EndOpenness;
			case 9:
			case 10: return animationData.EndOffset;
			case 11: return animationData.EndBrightness;
		}
		return 0;
	}
}

//=============================================================================
// * UltraHUDComponent_AnimationGroup
//=============================================================================
class UltraHUDComponent_AnimationGroup {
	constructor() {
		this.initialize(...arguments);
	}

	initialize() {
		this.onAllAnimationsComplete = new UltraSignal();
		this._completedAnimationCount = 0;
		this._animations = [];
	}

	isValid() {
		return this._animations.length > 0;
	}

	addAnimation(animation) {
		this._animations.push(animation);
		animation.onAnimationComplete.run(this.onOneAnimationCompleted.bind(this));
	}

	startAllAnimations(reverse) {
		this._completedAnimationCount = 0;
		const len = this._animations.length;
		for(let i = 0; i < len; i++) {
			if(reverse) {
				this._animations[i].startReversed();
			} else {
				this._animations[i].start();
			}
		}
	}

	onOneAnimationCompleted() {
		this._completedAnimationCount++;
		if(this._completedAnimationCount >= this._animations.length) {
			this.onAllAnimationsComplete.trigger();
			this._completedAnimationCount = 0;
		}
	}

	setImmediateState(state) {
		const len = this._animations.length;
		for(let i = 0; i < len; i++) {
			this._animations[i].setImmediateState(state);
		}
	}
}

//=============================================================================
// * Sprite_UltraHUDComponent_Text
//=============================================================================
class Sprite_UltraHUDComponent_Text extends Sprite_UltraHUDComponent {
	initialize(data, hud) {
		super.initialize(data, hud);
		this._margin = this.textMargin();
		this.setupText();
		this.setupDynamicText();
	}

	textMargin() {
		return 12;
	}

	setupText() {
		const textData = this._data.TextData;
		const fontSize = this._hud.getConfig().processDynamicInput(textData.FontSize || 0, true);
		const outlineSize = this._hud.getConfig().processDynamicInput(textData.OutlineSize || 0, true);
		const outlineOpacity = this._hud.getConfig().processDynamicInput(textData.OutlineOpacity || 50, true);
		const width = textData.MaxWidth + (this._margin * 2);
		const height = fontSize + (outlineSize * 2) + (this._margin * 2);
		if(!this.bitmap) {
			this.bitmap = new Bitmap(width, height);
		} else if(this.bitmap.width !== width && this.bitmap.height !== height) {
			this.resizeBitmap(width, height);
		}
		this.bitmap.textColor = textData.Color;
		this.bitmap.fontFace = UltraHUDManager.getFontFamily(textData.FontFamily);
		this.bitmap.fontSize = fontSize;
		this.bitmap.outlineWidth = outlineSize;
		this.bitmap.outlineColor = UltraUtils.createOpacityColor(textData.OutlineColor, outlineOpacity / 100);
		this._dataAlign = textData.Alignment;
	}

	setupDynamicText() {
		this._dynamicText = new UltraDynamicText(this._data.TextData.Text, this._hud.getConfig());
		this._dynamicText.onChange.run(this.renderBitmap.bind(this));
		this._dynamicText.start();
	}

	renderBitmap(newText) {
		const m = this._margin;
		const m2 = m * 2;
		const align = UltraUtils.convertNumberAlignToText(this._dataAlign);
		this.bitmap.clear();
		this.bitmap.drawText(newText, m, m, this.bitmap.width - m2, this.bitmap.height - m2, align);
	}

	update() {
		super.update();
		if(this._dynamicText !== null) {
			this._dynamicText.update();
		}
	}

	destroy() {
		super.destroy();
		if(this._dynamicText !== null) {
			this._dynamicText.destroy();
			this._dynamicText = null;
		}
	}
}

//=============================================================================
// * Sprite_UltraHUDComponent_Shape
//=============================================================================
class Sprite_UltraHUDComponent_Shape extends Sprite_UltraHUDComponent {
	initialize(data, hud) {
		super.initialize(data, hud);
		this.setupShape();
	}

	setupShape() {
		const shapeData = this._data.ShapeData;
		const outlineSize = this._hud.getConfig().processDynamicInput(shapeData.OutlineSize || 0, true);
		const outlineOpacity = this._hud.getConfig().processDynamicInput(shapeData.OutlineOpacity || 50, true);
		this._needRedraw = false;
		this._shape = shapeData.Shape;
		this._color = shapeData.Color;
		this._outlineColor = UltraUtils.createOpacityColor(shapeData.OutlineColor, outlineOpacity / 100);
		this._outlineSize = outlineSize;
		this.setComponentSize(shapeData.Width, shapeData.Height);
	}

	setComponentSize(width, height) {
		this._componentWidth = width;
		this._componentHeight = height;
		this.prepareToRender();
	}

	setComponentWidth(val) {
		this.setComponentSize(val, this._componentHeight);
	}

	setComponentHeight(val) {
		this.setComponentSize(this._componentWidth, val);
	}

	prepareToRender() {
		this._needRedraw = true;
	}

	renderBitmap() {
		let render = false;
		if(!this.bitmap) {
			this.bitmap = new Bitmap(this._componentWidth, this._componentHeight);
			render = true;
		} else if(this.bitmap.width !== this._componentWidth || this.bitmap.height !== this._componentHeight) {
			this.resizeBitmap(this._componentWidth, this._componentHeight);
			this.bitmap.clear();
			render = true;
		}
		if(render) {
			if(this._shape === 0) {
				this.renderRectangle();
			} else if(this._shape === 1) {
				this.renderEllipse();
			}
		}
	}

	renderRectangle() {
		const o = this._outlineSize;
		if(o > 0) {
			this.bitmap.fillRectOutline(0, 0, this._componentWidth, this._componentHeight, o, this._outlineColor);
		}
		this.bitmap.fillRect(o, o, this._componentWidth - (o * 2), this._componentHeight - (o * 2), this._color);
	}

	renderEllipse() {
		const o = this._outlineSize;
		if(o > 0) {
			this.bitmap.fillEllipse(0, 0, this._componentWidth, this._componentHeight, this._outlineColor);
		}
		this.bitmap.fillEllipse(o, o, this._componentWidth - (o * 2), this._componentHeight - (o * 2), this._color);
	}

	update() {
		super.update();
		if(this._needRedraw) {
			this.renderBitmap();
			this._needRedraw = false;
		}
	}
}

//=============================================================================
// * Sprite_UltraHUDComponent_Picture
//=============================================================================
class Sprite_UltraHUDComponent_Picture extends Sprite_UltraHUDComponent {
	initialize(data, hud) {
		super.initialize(data, hud);
		this._dynamicText = null;
		this.setupPicture();
	}

	setupPicture() {
		const pictureData = this._data.PictureData;
		if(pictureData.Code) {
			this.setupDynamicText();
		} else {
			this.renderBitmap("img/pictures/" + pictureData.Picture + ".png");
		}
	}

	setupDynamicText() {
		this._dynamicText = new UltraDynamicText({ Type: 7, Code: this._data.PictureData.Code }, this._hud.getConfig());
		this._dynamicText.onChange.run(this.renderBitmap.bind(this));
		this._dynamicText.start();
	}

	renderBitmap(path) {
		this.bitmap = ImageManager.loadBitmapFromUrl(path);
	}

	update() {
		super.update();
		if(this._dynamicText !== null) {
			this._dynamicText.update();
		}
	}

	destroy() {
		super.destroy();
		if(this._dynamicText !== null) {
			this._dynamicText.destroy();
			this._dynamicText = null;
		}
	}
}

//=============================================================================
// * Sprite_UltraHUDComponent_Repeat
//=============================================================================
class Sprite_UltraHUDComponent_Repeat extends Sprite_UltraHUDComponent {
	initialize(data, hud) {
		super.initialize(data, hud);
		this._dynamicText = null;
		this._tilingSprite = null;
		this.setupRepeat();
	}

	setupRepeat() {
		const repeatData = this._data.RepeatData;
		this._tilingSprite = this.createRepeatSprite(repeatData);
		this.addChild(this._tilingSprite);
		if(repeatData.Code) {
			this.setupDynamicText();
		} else {
			this.renderBitmap("img/pictures/" + repeatData.Picture + ".png");
		}
	}

	createRepeatSprite(repeatData) {
		const result = new TilingSprite();
		result.anchor.set(0.5);
		result.origin.set(repeatData.OffsetX, repeatData.OffsetY);
		result.width = repeatData.Width;
		result.height = repeatData.Height;
		return result;
	}

	setupDynamicText() {
		this._dynamicText = new UltraDynamicText({ Type: 7, Code: this._data.RepeatData.Code }, this._hud.getConfig());
		this._dynamicText.onChange.run(this.renderBitmap.bind(this));
		this._dynamicText.start();
	}

	renderBitmap(path) {
		this._tilingSprite.bitmap = ImageManager.loadBitmapFromUrl(path);
	}

	setComponentWidth(val) {
		if(this._tilingSprite !== null) {
			this._tilingSprite.width = val;
		}
	}

	setComponentHeight(val) {
		if(this._tilingSprite !== null) {
			this._tilingSprite.height = val;
		}
	}

	setRepeatOffsetX(val) {
		if(this._tilingSprite !== null) {
			this._tilingSprite.origin.x = val;
		}
	}

	setRepeatOffsetY(val) {
		if(this._tilingSprite !== null) {
			this._tilingSprite.origin.y = val;
		}
	}

	update() {
		super.update();
		if(this._dynamicText !== null) {
			this._dynamicText.update();
		}
	}

	destroy() {
		super.destroy();
		if(this._dynamicText !== null) {
			this._dynamicText.destroy();
			this._dynamicText = null;
		}
	}
}

//=============================================================================
// * Sprite_UltraHUDComponent_Gauge
//=============================================================================
class Sprite_UltraHUDComponent_Gauge extends Sprite_UltraHUDComponent {
	initialize(data, hud) {
		super.initialize(data, hud);
		this._needRedraw = false;
		this._dynamicValue = null;
		this._dynamicMax = null;
		this._duration = 0;
		this._value = null;
		this._maximum = null;
		this._targetValue = null;
		this._targetMaximum = null;
		this._syncComponent = null;
		this.setupGauge();
	}

	setupGauge() {
		const gaugeData = this._data.GaugeData;
		const outlineSize = this._hud.getConfig().processDynamicInput(gaugeData.OutlineSize || 0, true);
		const outlineOpacity = this._hud.getConfig().processDynamicInput(typeof gaugeData.OutlineOpacity === "number" ? gaugeData.OutlineOpacity : 50, true);
		this._gaugeWidth = gaugeData.Width;
		this._gaugeHeight = gaugeData.Height;
		this._outlineSize = outlineSize;
		this._color1 = gaugeData.Color1;
		this._color2 = gaugeData.Color2;
		this._backgroundColor = gaugeData.BackgroundColor;
		this._outlineColor = UltraUtils.createOpacityColor(gaugeData.OutlineColor, outlineOpacity / 100);
		this._smoothness = this._hud.getConfig().processDynamicInput(typeof gaugeData.Smoothness === "number" ? gaugeData.Smoothness : 20, true);
		this._syncComponentName = this._hud.getConfig().processDynamicInput(gaugeData.SyncComponent || "", true);
		this.setupDynamicValue();
		this.setupDynamicMax();
	}

	setupDynamicValue() {
		this._dynamicValue = new UltraDynamicNumber(this._data.GaugeData.Value, this._hud.getConfig());
		this._dynamicValue.onChange.run(this.setGaugeValue.bind(this));
		this._dynamicValue.start();
	}

	setupDynamicMax() {
		this._dynamicMax = new UltraDynamicNumber(this._data.GaugeData.Maximum, this._hud.getConfig());
		this._dynamicMax.onChange.run(this.setGaugeMaximum.bind(this));
		this._dynamicMax.start();
	}

	onCreationComplete() {
		this.setupSyncComponent();
	}

	setupSyncComponent() {
		if(typeof this._syncComponentName === "string" && this._syncComponentName.length > 0) {
			const syncComp = this._hud.findComponentByName(this._syncComponentName);
			if(syncComp && syncComp.isTextComponent()) {
				this._syncComponent = syncComp;
			}
		}
	}

	prepareToRender() {
		this._needRedraw = true;
	}

	renderBitmap() {
		if(!this.bitmap) {
			this.bitmap = new Bitmap(this._gaugeWidth, this._gaugeHeight);
		} else if(this.bitmap.width !== this._gaugeWidth || this.bitmap.height !== this._gaugeHeight) {
			this.resizeBitmap(this._gaugeWidth, this._gaugeHeight);
		}
		const value = this._value;
		const max = this._maximum;
		const rate = max > 0 ? (value / max).clamp(0, 1) : 0;
		const outline = this._outlineSize;
		const outline2 = outline * 2;
		const fillW = Math.floor((this._gaugeWidth - outline2) * rate);
		const fillH = this._gaugeHeight - outline2;
		this.bitmap.clear();
		this.bitmap.fillRect(0, 0, this._gaugeWidth, this._gaugeHeight, this._outlineColor);
		this.bitmap.fillRect(outline, outline, this._gaugeWidth - outline2, fillH, this._backgroundColor);
		this.bitmap.gradientFillRect(outline, outline, fillW, fillH, this._color1, this._color2);
		this.updateSyncComponent();
	}

	updateSyncComponent() {
		if(this._syncComponent !== null) {
			this._syncComponent.renderBitmap(String(Math.round(this._value)));
		}
	}

	setComponentWidth(val) {
		this._gaugeWidth = val;
		this.prepareToRender();
	}

	setComponentHeight(val) {
		this._gaugeHeight = val;
		this.prepareToRender();
	}

	smoothness() {
		return this._smoothness;
	}

	isSmooth() {
		return this._smoothness > 0;
	}

	setGaugeValue(value) {
		if(this._value === null) {
			this._value = value;
			this._targetValue = this._value;
			this.prepareToRender();
		} else if(this._value !== value) {
			this._targetValue = value;
			this._duration = this.smoothness();
			if(!this.isSmooth()) {
				this._value = value;
				this.prepareToRender();
			}
		}
	}

	setGaugeMaximum(value) {
		if(this._maximum === null) {
			this._maximum = value;
			this._targetMaximum = this._maximum;
			this.prepareToRender();
		} else if(this._maximum !== value) {
			this._targetMaximum = value;
			this._duration = this.smoothness();
			if(!this.isSmooth()) {
				this._maximum = value;
				this.prepareToRender();
			}
		}
	}

	update() {
		super.update();
		if(this._dynamicValue !== null) {
			this._dynamicValue.update();
		}
		if(this._dynamicMax !== null) {
			this._dynamicMax.update();
		}
		this.updateGaugeAnimation();
		if(this._needRedraw) {
			this.renderBitmap();
			this._needRedraw = false;
		}
	}

	updateGaugeAnimation() {
		if (this._duration > 0) {
			const d = this._duration;
			this._value = (this._value * (d - 1) + this._targetValue) / d;
			this._maximum = (this._maximum * (d - 1) + this._targetMaximum) / d;
			this._duration--;
			this.prepareToRender();
		} else if(!this.isSmooth()) {
			this.setGaugeValue(this._targetValue);
			this.setGaugeMaximum(this._targetMaximum);
		}
	}

	destroy() {
		super.destroy();
		if(this._dynamicValue !== null) {
			this._dynamicValue.destroy();
			this._dynamicValue = null;
		}
		if(this._dynamicMax !== null) {
			this._dynamicMax.destroy();
			this._dynamicMax = null;
		}
	}
}

//=============================================================================
// * Sprite_UltraHUDComponent_PictureGauge
//=============================================================================
class Sprite_UltraHUDComponent_PictureGauge extends Sprite_UltraHUDComponent {
	initialize(data, hud) {
		super.initialize(data, hud);
		this._needRedraw = false;
		this._dynamicValue = null;
		this._dynamicMax = null;
		this._duration = 0;
		this._value = null;
		this._maximum = null;
		this._targetValue = null;
		this._targetMaximum = null;
		this._syncComponent = null;
		this.setupGauge();
	}

	setupGauge() {
		const gaugeData = this._data.PictureGaugeData;
		this._gaugeWidth = gaugeData.Width;
		this._edgeMargin = this._hud.getConfig().processDynamicInput(typeof gaugeData.EdgeMargin === "number" ? gaugeData.EdgeMargin : 15, true);
		this._gaugeSkin = gaugeData.GaugeSkin;
		this._smoothness = this._hud.getConfig().processDynamicInput(typeof gaugeData.Smoothness === "number" ? gaugeData.Smoothness : 20, true);
		this._syncComponentName = this._hud.getConfig().processDynamicInput(gaugeData.SyncComponent || "", true);
		this.setupDynamicValue();
		this.setupDynamicMax();
		this.prepareToRender();
	}

	setupDynamicValue() {
		this._dynamicValue = new UltraDynamicNumber(this._data.PictureGaugeData.Value, this._hud.getConfig());
		this._dynamicValue.onChange.run(this.setGaugeValue.bind(this));
		this._dynamicValue.start();
	}

	setupDynamicMax() {
		this._dynamicMax = new UltraDynamicNumber(this._data.PictureGaugeData.Maximum, this._hud.getConfig());
		this._dynamicMax.onChange.run(this.setGaugeMaximum.bind(this));
		this._dynamicMax.start();
	}

	onCreationComplete() {
		this.setupSyncComponent();
	}

	setupSyncComponent() {
		if(typeof this._syncComponentName === "string" && this._syncComponentName.length > 0) {
			const syncComp = this._hud.findComponentByName(this._syncComponentName);
			if(syncComp && syncComp.isTextComponent()) {
				this._syncComponent = syncComp;
			}
		}
	}

	constructThreePiece(bitmap, y, width, margin, sprite, redrawAll) {
		const height = bitmap.height / 3;
		if(!redrawAll && sprite.bitmap && sprite.bitmap.width === width && sprite.bitmap.height === height) {
			return;
		}
		let result;
		if(sprite.bitmap) {
			result = sprite.bitmap;
			result.resize(width, height);
			result.clear();
		} else {
			result = new Bitmap(width, height);
		}
		const sWidth = bitmap.width;
		result.blt(bitmap, 0, y, margin, height, 0, 0);
		result.blt(bitmap, margin, y, sWidth - (margin * 2), height, margin, 0, width - (margin * 2));
		result.blt(bitmap, sWidth - margin, y, margin, height, width - margin, 0);
		sprite.bitmap = null;
		sprite.bitmap = result;
	}

	createPieces() {
		if(!this._background) {
			this._background = new Sprite();
			this._background.anchor.set(0.5);
			this.addChild(this._background);
		}
		if(!this._gauge) {
			this._gauge = new Sprite();
			this._gauge.anchor.set(0.5);
			this.addChild(this._gauge);
		}
		if(!this._foreground) {
			this._foreground = new Sprite();
			this._foreground.anchor.set(0.5);
			this.addChild(this._foreground);
		}
	}

	createBitmaps(sourceBitmap, redrawAll) {
		const gw = this._gaugeWidth;
		const m = this._edgeMargin;
		const h = sourceBitmap.height / 3;
		this.constructThreePiece(sourceBitmap, h * 2, gw, m, this._background, redrawAll);
		this.constructThreePiece(sourceBitmap, h, gw, m, this._gauge, redrawAll);
		this.constructThreePiece(sourceBitmap, 0, gw, m, this._foreground, redrawAll);
	}

	prepareToRender() {
		this._needRedraw = true;
	}

	renderBitmap() {
		const gaugeSkin = ImageManager.loadSystem(this._gaugeSkin);
		if(!gaugeSkin.isReady()) {
			gaugeSkin.addLoadListener(this.renderBitmap.bind(this));
			return;
		}

		let redrawAll = false;
		if(this._currentGaugeSkin !== gaugeSkin.url) {
			this._currentGaugeSkin = gaugeSkin.url;
			redrawAll = true;
		}

		this.createPieces();
		this.createBitmaps(gaugeSkin, redrawAll);

		this.resizeGauge();
	}

	resizeGauge() {
		if(this._gauge) {
			const value = this._value;
			const max = this._maximum;
			const rate = max > 0 ? (value / max).clamp(0, 1) : 0;
			const fillW = Math.floor(this._gaugeWidth * rate);
			this._gauge.setFrame(0, 0, fillW, this._gauge.bitmap.height);
			this._gauge.x = (fillW - this._gaugeWidth) / 2;
			this.updateSyncComponent();
		}
	}

	updateSyncComponent() {
		if(this._syncComponent !== null) {
			this._syncComponent.renderBitmap(String(Math.round(this._value)));
		}
	}

	setComponentWidth(val) {
		this._gaugeWidth = val;
		this.prepareToRender();
	}

	setComponentHeight(val) {
		this._gaugeHeight = val;
		this.prepareToRender();
	}

	smoothness() {
		return this._smoothness;
	}

	setGaugeValue(value) {
		if(this._value === null) {
			this._value = value;
			this._targetValue = this._value;
			this.prepareToRender();
		} else if(this._value !== value) {
			this._targetValue = value;
			this._duration = this.smoothness();
		}
	}

	setGaugeMaximum(value) {
		if(this._maximum === null) {
			this._maximum = value;
			this._targetMaximum = this._maximum;
			this.resizeGauge();
		} else if(this._maximum !== value) {
			this._targetMaximum = value;
			this._duration = this.smoothness();
		}
	}

	update() {
		super.update();
		if(this._dynamicValue !== null) {
			this._dynamicValue.update();
		}
		if(this._dynamicMax !== null) {
			this._dynamicMax.update();
		}
		this.updateGaugeAnimation();
		if(this._needRedraw) {
			this.renderBitmap();
			this._needRedraw = false;
		}
	}

	updateGaugeAnimation() {
		if (this._duration > 0) {
			const d = this._duration;
			this._value = (this._value * (d - 1) + this._targetValue) / d;
			this._maximum = (this._maximum * (d - 1) + this._targetMaximum) / d;
			this._duration--;
			this.resizeGauge();
		} else if(this._value !== this._targetValue || this._maximum !== this._targetMaximum) {
			this._value = this._targetValue;
			this._maximum = this._targetMaximum;
			this.resizeGauge();
		}
	}

	destroy() {
		super.destroy();
		if(this._dynamicValue !== null) {
			this._dynamicValue.destroy();
			this._dynamicValue = null;
		}
		if(this._dynamicMax !== null) {
			this._dynamicMax.destroy();
			this._dynamicMax = null;
		}
	}
}

//=============================================================================
// * Sprite_UltraHUDComponent_Group
//=============================================================================
class Sprite_UltraHUDComponent_Group extends Sprite_UltraHUDComponent {
	initialize(data, hud) {
		super.initialize(data, hud);
		this.setupGroup();
	}

	setupGroup() {
	}

	hasChildComponents() {
		return true;
	}
}

//=============================================================================
// * Sprite_UltraHUDComponent_Window
//=============================================================================
class Sprite_UltraHUDComponent_Window extends Sprite_UltraHUDComponent {
	initialize(data, hud) {
		super.initialize(data, hud);
		this._baseY = this._data.Y;
		this.setupSize();
		this.setupWindow();
	}

	setupSize() {
		const windowData = this._data.WindowData;
		this._windowWidth = windowData.Width;
		this._windowHeight = windowData.Height;
	}

	setupWindow() {
		const windowData = this._data.WindowData;
		const padding = this._hud.getConfig().processDynamicInput(typeof windowData.Padding === "number" ? windowData.Padding : 12, true);
		const margin = this._hud.getConfig().processDynamicInput(typeof windowData.Margin === "number" ? windowData.Margin : 4, true);
		const backgroundOpacity = this._hud.getConfig().processDynamicInput(typeof windowData.BackgroundOpacity === "number" ? windowData.BackgroundOpacity : 75, true);
		this._window = new Window_Base(new Rectangle(0, 0, this._windowWidth, this._windowHeight));
		this._window.windowSkin = ImageManager.loadSystem(windowData.WindowSkin);
		this._window.padding = padding;
		this._window.margin = margin;
		this._window.backOpacity = (backgroundOpacity / 100) * 255;
		this.addChild(this._window);
		this.resetWindowPosition();
	}

	hasChildComponents() {
		return true;
	}

	setComponentWidth(v) {
		if(this._windowWidth !== v) {
			this._windowWidth = v;
			if(this._window) {
				this._window.width = this._windowWidth;
				this.resetWindowPosition();
			}
		}
	}

	setComponentHeight(v) {
		if(this._windowHeight !== v) {
			this._windowHeight = v;
			if(this._window) {
				this._window.height = this._windowHeight;
				this.resetWindowPosition();
			}
		}
	}

	setComponentOpenness(v) {
		if(this._window) {
			v = v.clamp(0, 255);
			this.scale.y = v / 255;
		}
	}

	resetWindowPosition() {
		this._window.x = this._windowWidth / -2;
		this._window.y = this._windowHeight / -2;
	}
}

//=============================================================================
// * Sprite_UltraHUDComponent_ActorFace
//=============================================================================
class Sprite_UltraHUDComponent_ActorFace extends Sprite_UltraHUDComponent {
	initialize(data, hud) {
		super.initialize(data, hud);
		this._dynamicActorID = null;
		this._oldActor = null;
		this._oldActorSignalId = null;
		this.setupDynamicActorID();
	}

	setupDynamicActorID() {
		this._dynamicActorID = new UltraDynamicActorID(this._data.ActorFaceData.ActorID, this._hud.getConfig());
		this._dynamicActorID.onChange.run(this.renderBitmap.bind(this));
		this._dynamicActorID.start();
	}

	renderBitmap(actorId) {
		const actor = $gameActors.actor(actorId);
		if(actor) {
			if(this._oldActor !== null && this._oldActorSignalId !== null && this._oldActor.getOnFaceChangeSignal()) {
				this._oldActor.getOnFaceChangeSignal().remove(this._oldActorSignalId);
				this._oldActor = null;
				this._oldActorSignalId = null;
			}
			this.renderBitmapInternal(actor);
			if(actor && actor.getOnFaceChangeSignal()) {
				this._oldActor = actor;
				this._oldActorSignalId = actor.getOnFaceChangeSignal().run(this.renderBitmapInternal.bind(this, actor));
			} else {
				this._oldActor = null;
				this._oldActorSignalId = null;
			}
		}
	}

	renderBitmapInternal(actor, actorId) {
		if(!this.bitmap) {
			this.bitmap = new Bitmap(ImageManager.faceWidth, ImageManager.faceHeight);
		}
		const faceName = actor.faceName();
		const faceNameBitmap = ImageManager.loadFace(faceName);
		if(faceNameBitmap.isReady()) {
			this.bitmap.clear();
			Window_Base.prototype.drawFace.call({ contents: this.bitmap }, faceName, actor.faceIndex(), 0, 0);
		} else {
			faceNameBitmap.addLoadListener(this.renderBitmapInternal.bind(this, actor, actorId));
		}
	}

	update() {
		super.update();
		if(this._dynamicActorID !== null) {
			this._dynamicActorID.update();
		}
	}

	destroy() {
		super.destroy();
		if(this._dynamicActorID !== null) {
			this._dynamicActorID.destroy();
			this._dynamicActorID = null;
		}
	}
}

//=============================================================================
// * Sprite_UltraHUDComponent_IconSet
//=============================================================================
class Sprite_UltraHUDComponent_IconSet extends Sprite_UltraHUDComponent {
	initialize(data, hud) {
		super.initialize(data, hud);
		this._dynamicIconIndex = null;
		this._dynamicText = null;
		this.setupIcon();
	}

	setupIcon() {
		const iconData = this._data.IconData;
		if(iconData.Code) {
			this.setupDynamicText();
		} else {
			this.renderBitmap("img/system/" + iconData.IconSet + ".png");
		}
		this._iconSize = this._hud.getConfig().processDynamicInput(iconData.IconSize || 32, true);
		this.setupDynamicIconIndex(iconData.IconIndex);
	}

	setupDynamicText() {
		this._dynamicText = new UltraDynamicText({ Type: 7, Code: this._data.Code }, this._hud.getConfig());
		this._dynamicText.onChange.run(this.renderBitmap.bind(this));
		this._dynamicText.start();
	}

	setupDynamicIconIndex(iconIndexData) {
		this._dynamicIconIndex = new UltraDynamicNumber(iconIndexData, this._hud.getConfig());
		this._dynamicIconIndex.onChange.run(this.setupFrame.bind(this));
		this._dynamicIconIndex.start();
	}

	renderBitmap(path) {
		this.bitmap = ImageManager.loadBitmapFromUrl(path);
		if(!this.bitmap.isReady()) {
			this.bitmap.addLoadListener(this.refreshFrame.bind(this));
		} else {
			this.refreshFrame();
		}
	}

	refreshFrame() {
		if(this._dynamicIconIndex !== null) {
			this.setupFrame(this._dynamicIconIndex.currentNumber);
		}
	}

	setupFrame(index) {
		const iconSize = this._iconSize;
		const sx = (index % 16) * iconSize;
		const sy = Math.floor(index / 16) * iconSize;
		this.setFrame(sx, sy, iconSize, iconSize);
	}

	update() {
		super.update();
		if(this._dynamicText !== null) {
			this._dynamicText.update();
		}
		if(this._dynamicIconIndex !== null) {
			this._dynamicIconIndex.update();
		}
	}

	destroy() {
		super.destroy();
		if(this._dynamicText !== null) {
			this._dynamicText.destroy();
			this._dynamicText = null;
		}
		if(this._dynamicIconIndex !== null) {
			this._dynamicIconIndex.destroy();
			this._dynamicIconIndex = null;
		}
	}
}

//=============================================================================
// * DataManager
//=============================================================================
$.DataManager = $.DataManager || {};

$.DataManager.createGameObjects = DataManager.createGameObjects;
DataManager.createGameObjects = function() {
	$.DataManager.createGameObjects.apply(this, arguments);
	$gameUltraHUD = new Game_UltraHUD();
};

$.DataManager.makeSaveContents = DataManager.makeSaveContents;
DataManager.makeSaveContents = function() {
	const contents = $.DataManager.makeSaveContents.apply(this, arguments);
	contents.ultraHUD = $gameUltraHUD;
	return contents;
};

$.DataManager.extractSaveContents = DataManager.extractSaveContents;
DataManager.extractSaveContents = function(contents) {
	$.DataManager.extractSaveContents.apply(this, arguments);
	$gameUltraHUD = contents.ultraHUD;
};

//=============================================================================
// * SceneManager
//=============================================================================
$.SceneManager = $.SceneManager || {};

if($.screenshots && Utils.isNwjs()) {

$.SceneManager.onKeyDown = SceneManager.onKeyDown;
SceneManager.onKeyDown = function(event) {
	$.SceneManager.onKeyDown.apply(this, arguments);
	if(event.ctrlKey && !event.altKey) {
		switch (event.keyCode) {
			case 83: {
				SceneManager.takeScreenShot_HUDMakerUltra();
				break;
			}
		}
	}
};

SceneManager.takeScreenShot_HUDMakerUltra = function() {
	if(!$.fileSaverElement) {
		$.fileSaverElement = document.createElement("input");
		$.fileSaverElement.type = "file";
		$.fileSaverElement.style = "display:none";
		$.fileSaverElement.accept = "image/png"
		$.fileSaverElement.nwsaveas = "Screenshot.png";
		$.fileSaverElement.nwworkingdir = StorageManager.fileDirectoryPath().replace(/[\\\/]save[\\\/]$/, "");
		$.fileSaverElement.addEventListener("change", this.saveScreenShot_HUDMakerUltra, false);
	}

	$.fileSaverElement.click();
};

SceneManager.saveScreenShot_HUDMakerUltra = function(event) {
	const scene = SceneManager._scene;
	if(scene && scene._ultraHudContainer) {
		scene._ultraHudContainer.visible = false;
		const path = this.value;
		const result = SceneManager.snap().canvas.toDataURL("image/png").replace(/^[\w:\/;]+,/, "");
		require("fs").writeFileSync(path, result, "base64");
		scene._ultraHudContainer.visible = true;
	}
};

}

//=============================================================================
// * Scene_Boot
//=============================================================================
class Scene_Boot {
	onDatabaseLoaded() {
		$.Scene_Boot.onDatabaseLoaded.apply(this, arguments);
		UltraHUDManager.preloadHUDMakerUltraFonts();
	}
}

//=============================================================================
// * Scene_Map
//=============================================================================
class Scene_Map {
	initialize() {
		$.Scene_Map.initialize.apply(this, arguments);
		this._ultraHudContainer = null;
		this._shouldHUDBeAvailable = false;
	}

	createSpriteset() {
		$.Scene_Map.createSpriteset.apply(this, arguments);
		this.createUltraHUD();
	}

	createUltraHUD() {
		this._ultraHudContainer = new Stage_UltraHUDContainer(true);
		this._ultraHudContainer.createMapHUD();
		this.addChild(this._ultraHudContainer);
		this.updateUltraHUDContainerVisibility();
	}

	updateMenuButton() {
		this.updateUltraHUDContainerVisibility();
		$.Scene_Map.updateMenuButton.apply(this, arguments);
	}

	shouldHUDBeAvailable() {
		return !$gameMap.isEventRunning();
	};

	updateUltraHUDContainerVisibility() {
		const hudEnabled = this.shouldHUDBeAvailable();
		if(hudEnabled === this._shouldHUDBeAvailable && this._ultraHudContainer !== null) {
			this._ultraHudContainer.visible = this.ultraHUDVisibility();
			this._ultraHudContainer.setVisibilityState(!($.hideDuringEvents && !hudEnabled));
		}
        if (hudEnabled !== this._shouldHUDBeAvailable) {
            this._shouldHUDBeAvailable = hudEnabled;
        }
	}

	ultraHUDVisibility() {
		return ($.mapVisibilityFunc === null ? true : $.mapVisibilityFunc()) && $gameUltraHUD.globalVisibility;
	}

	refreshUltraHUD() {
		if(this._ultraHudContainer !== null) {
			this._ultraHudContainer.refreshUltraHUD();
		}
	}

	destroyUltraHUD() {
		if(this._ultraHudContainer !== null) {
			this._ultraHudContainer.destroyCurrentHUD();
			this.removeChild(this._ultraHudContainer);
			this._ultraHudContainer.destroy();
			this._ultraHudContainer = null;
		}
	}

	terminate() {
		this.destroyUltraHUD();
		$.Scene_Map.terminate.apply(this, arguments);
	}
}

//=============================================================================
// * Scene_Battle
//=============================================================================
class Scene_Battle {
	initialize() {
		$.Scene_Battle.initialize.apply(this, arguments);
		this._ultraHudContainer = null;
	}

	createSpriteset() {
		$.Scene_Battle.createSpriteset.apply(this, arguments);
		this.createUltraHUD();
	}

	createUltraHUD() {
		this._ultraHudContainer = new Stage_UltraHUDContainer(false);
		this._ultraHudContainer.createMapHUD();
		this.addChild(this._ultraHudContainer);
		this.updateUltraHUDContainerVisibility();
	}

	updateMenuButton() {
		$.Scene_Battle.updateMenuButton.apply(this, arguments);
		this.updateUltraHUDContainerVisibility();
	}

	updateUltraHUDContainerVisibility() {
		if(this._ultraHudContainer !== null) {
			this._ultraHudContainer.visible = this.ultraHUDVisibility();
			this._ultraHudContainer.setVisibilityState(!($.hideDuringEvents && $gameTroop.isEventRunning()));
		}
	}

	ultraHUDVisibility() {
		return ($.battleVisibilityFunc === null ? true : $.battleVisibilityFunc()) && $gameUltraHUD.globalVisibility;
	}

	refreshUltraHUD() {
		if(this._ultraHudContainer !== null) {
			this._ultraHudContainer.refreshUltraHUD();
		}
	}

	destroyUltraHUD() {
		if(this._ultraHudContainer !== null) {
			this._ultraHudContainer.destroyCurrentHUD();
			this.removeChild(this._ultraHudContainer);
			this._ultraHudContainer.destroy();
			this._ultraHudContainer = null;
		}
	}

	terminate() {
		this.destroyUltraHUD();
		$.Scene_Battle.terminate.apply(this, arguments);
	}
}

if($.hideStatusWindow || $.hideSelectionWindow) {

$.Scene_Battle = $.Scene_Battle || {};

if($.hideStatusWindow) {

	$.Scene_Battle.updateStatusWindowVisibility = Scene_Battle.prototype.updateStatusWindowVisibility;
	Scene_Battle.prototype.updateStatusWindowVisibility = function() {
		$.Scene_Battle.updateStatusWindowVisibility.apply(this, arguments);
		this._statusWindow.visible = false;
	};

	$.Scene_Battle.createStatusWindow = Scene_Battle.prototype.createStatusWindow;
	Scene_Battle.prototype.createStatusWindow = function() {
		$.Scene_Battle.createStatusWindow.apply(this, arguments);

		// Maybe a bit of a weird way to handle this?
		// But most compatible and consistent way to achieve the desired behavior(?)
		this._statusWindow.__srd_hudmakeultra_show = this._statusWindow.show;
		this._statusWindow.show = function() {
			this.__srd_hudmakeultra_show.apply(this, arguments);
			this.visible = false;
		};
	};

}

if($.hideSelectionWindow) {

	$.Scene_Battle.update = Scene_Battle.prototype.update;
	Scene_Battle.prototype.update = function() {
		$.Scene_Battle.update.apply(this, arguments);

		// Same thing as the status window. This may be a bit scuffed, 
		// but is probably best since making these windows invisible disables their functionality.
		this._actorWindow.x = 999999;
		this._enemyWindow.x = 999999;
	};

}

}

//=============================================================================
// * setupAutoReload
//=============================================================================
if($.autoReload) {

function setupAutoReload() {
	UltraHUDManager.checkHUDDataString(true);
	const win = nw.Window.get();
	win.on("focus", UltraHUDManager.checkHUDDataString.bind(UltraHUDManager));
}

setupAutoReload();

}

//=============================================================================
// * Plugin Commands
//=============================================================================

PluginManager.registerCommand("SRD_HUDMakerUltra", "Set HUD Visibility", function(params) {
	const visible = String(params["Visible?"]).trim().toLowerCase() === "true";
	$gameUltraHUD.setGlobalVisibility(!!visible);
});

PluginManager.registerCommand("SRD_HUDMakerUltra", "Set HUD Activity", function(params) {
	const active = String(params["Active?"]).trim().toLowerCase() === "true";
	$gameUltraHUD.setGlobalActiveness(!!active);
});

//=============================================================================
// * Plugin Exports
//=============================================================================
const exports = window;
exports.UltraHUDManager                       = UltraHUDManager;
exports.Game_UltraHUD                         = Game_UltraHUD;
exports.HUDMakerUltraProcessConfiguration     = HUDMakerUltraProcessConfiguration;
exports.Stage_UltraHUDContainer               = Stage_UltraHUDContainer;
exports.Sprite_UltraHUD                       = Sprite_UltraHUD;
exports.Sprite_UltraHUDComponent              = Sprite_UltraHUDComponent;
exports.UltraHUDComponent_Animation           = UltraHUDComponent_Animation;
exports.UltraHUDComponent_AnimationGroup      = UltraHUDComponent_AnimationGroup;
exports.Sprite_UltraHUDComponent_Text         = Sprite_UltraHUDComponent_Text;
exports.Sprite_UltraHUDComponent_Shape        = Sprite_UltraHUDComponent_Shape;
exports.Sprite_UltraHUDComponent_Picture      = Sprite_UltraHUDComponent_Picture;
exports.Sprite_UltraHUDComponent_Gauge        = Sprite_UltraHUDComponent_Gauge;
exports.Sprite_UltraHUDComponent_PictureGauge = Sprite_UltraHUDComponent_PictureGauge;
exports.Sprite_UltraHUDComponent_Group        = Sprite_UltraHUDComponent_Group;
exports.Sprite_UltraHUDComponent_Window       = Sprite_UltraHUDComponent_Window;
exports.Sprite_UltraHUDComponent_ActorFace    = Sprite_UltraHUDComponent_ActorFace;

//=============================================================================
// * MergeClass
// *
// * Never stagnate. Never stagnate. Never stagnate.
//=============================================================================
function MergeClass(es6Class, name) {
	const className = name || es6Class.prototype.constructor.name;
	const classObj = window[className];
	if(classObj) {
		$[className] = $[className] || {};
		Object.getOwnPropertyNames(es6Class.prototype).forEach(function(name) {
			if(name === "constructor") return;
			if(classObj.prototype[name]) {
				$[className][name] = classObj.prototype[name];
			}
			classObj.prototype[name] = es6Class.prototype[name];
		});
	}
}

MergeClass(Scene_Boot);
MergeClass(Scene_Map);
MergeClass(Scene_Battle);

})(SRD.HUDMakerUltra);
