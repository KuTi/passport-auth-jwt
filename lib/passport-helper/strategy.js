var passport = require('passport-strategy'),
	auth_hdr = require('./auth_header'),
	util = require('util'),
	url = require('url'),
	ENV = NODE;


/**
 * Strategy constructor
 *
 * @param options
 *          secretOrKey: (REQUIRED) String or buffer containing the secret or PEM-encoded public key
 *          jwtFromRequest: (REQUIRED) Function that accepts a reqeust as the only parameter and returns the either JWT as a string or null
 *          issuer: If defined issuer will be verified against this value
 *          audience: If defined audience will be verified against this value
 *          algorithms: List of strings with the names of the allowed algorithms. For instance, ["HS256", "HS384"].
 *          ignoreExpiration: if true do not validate the expiration of the token.
 *          passReqToCallback: If true the, the verify callback will be called with args (request, jwt_payload, done_callback).
 * @param verify - Verify callback with args (jwt_payload, done_callback) if passReqToCallback is false,
 *                 (request, jwt_payload, done_callback) if true.
 */
function JwtStrategy(options, verify) {
	passport.Strategy.call(this);
	this.name = 'passport-auth-jwt';

	this._secret = options['secret'];
	this._key = options['key'];

	if (!this._secret && !this._key) {
		throw new TypeError('[Passport Auth JWT] requires a secret or key');
	}

	if (this._secret && this._key) {
		console.log('[Passport Auth JWT] use "key" for default create JWT');
	}

	this._verify = verify;

	if (!this._verify) {
		throw new TypeError('[Passport Auth JWT] requires a verify callback');
	}

	this._passReqToCallback = true;
	this._getTokenFromRequest = options.getTokenFromRequest;

	this._verifOpts = {};

	if (options.issuer) {
		this._verifOpts.issuer = options.issuer;
	}

	if (options.audience) {
		this._verifOpts.audience = options.audience;
	}

	if (options.algorithms) {
		this._verifOpts.algorithms = options.algorithms;
	}

	if (options.ignoreExpiration != null) {
		this._verifOpts.ignoreExpiration = options.ignoreExpiration;
	}
}

util.inherits(JwtStrategy, passport.Strategy);

/**
 * Allow for injection of JWT Verifier.
 *
 * This improves testability by allowing tests to cleanly isolate failures in the JWT Verification
 * process from failures in the passport related mechanics of authentication.
 *
 * Note that this should only be replaced in tests.
 */
JwtStrategy.JwtVerifier = require('./verify_jwt');


/**
 * Authenticate request based on JWT obtained from header or post body
 */
JwtStrategy.prototype.authenticate = function (req, options) {
	var self = this;

	var token = self._getTokenFromRequest(req);

	if (!token) {
		return self.fail(new Error("Can't get Token. Please "));
	}

	// Verify the JWT
	JwtStrategy.JwtVerifier(token, (this._key || this._secret), this._verifOpts, function (jwt_err, payload) {
		if (jwt_err) {
			return self.fail(jwt_err);
		} else {
			// Pass the parsed token to the user
			var verified = function (err, user, info) {
				if (err) {
					return self.error(err);
				} else if (!user) {
					return self.fail(info);
				} else {
					return self.success(user, info);
				}
			};

			try {
				if (self._passReqToCallback) {
					self._verify(req, payload, verified);
				} else {
					self._verify(payload, verified);
				}
			} catch (ex) {
				self.error(ex);
			}
		}
	});
};


/**
 * Export the Jwt Strategy
 */
module.exports = JwtStrategy;
