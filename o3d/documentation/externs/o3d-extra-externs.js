
/**
 * Special global variable for V8 instances.
 */
var plugin;

/**
 * The main namespace for the o3d plugin.
 * @constructor
 */
var o3d;

/**
 * @type {!Object}
 */
var Exception = goog.typedef;

/**
 * A namespace for the Cursor.
 * @namespace
 */
o3d.Cursor = o3d.Cursor || { };

/**
 * A namespace for the VectorMath.
 * @namespace
 */
var Vectormath;

/**
 * A namespace for the VectorMath.Aos
 * @namespace
 */
Vectormath.Aos = Vectormath.Aos || { };

/**
 * A stand-in class definition for Float32Array.
 * @param {number} size The size.
 * @constructor
 */
var Float32Array = function(size) { };

/**
 * A 4x4 Matrix of floats
 * @type {!Array.<!Array.<number>>}
 */
o3d.Matrix4 = goog.typedef;

/**
 * RangeError.
 * why is this sometimes needed and sometimes not?
 * @exception
 */
var RangeError;

