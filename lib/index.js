/**
 * Passport auth JWT
 */

var passport = require('passport');
var JwtStrategy = require('./passport-helper').Strategy;
var ExtractJwt = require('./passport-helper').ExtractJwt;
var error = require('./error');

/**
 * PassportAuthJWT
 *
 * @param config
 *          secret: (REQUIRED) String or buffer containing the secret or PEM-encoded public key
 *          jwtFromRequest: (REQUIRED) Function that accepts a reqeust as the only parameter and returns the either JWT as a string or null
 *          issuer: If defined issuer will be verified against this value
 *          audience: If defined audience will be verified against this value
 *          algorithms: List of strings with the names of the allowed algorithms. For instance, ["HS256", "HS384"].
 *          ignoreExpiration: if true do not validate the expiration of the token.
 *          passReqToCallback: If true the, the verify callback will be called with args (request, jwt_payload, done_callback).
 */

var PassportAuthJWT = function (config) {
	config = config || {};

	config.secret = config.key || config.secret;
	this._config = Object.assign(this._config, config);
	this._config.getTokenFromRequest = ExtractJwt.versionOneCompatibility(this._config.extractJwtOpts);
};

PassportAuthJWT.prototype = {
	_config: {
		clientId: 'client_id',
		extractJwtOpts: {
			authScheme: 'AuthJWT',
			tokenBodyField: 'access_token',
			tokenQueryParameterName: 'access_token'
		},
		requestTokenEndpoint: '/request-token',
		refreshTokenEndpoint: '/refresh-token',
		tokenEndpoint: '/token',
		ignoreRequestTokenUrl: ['/'],
		hook: {
			passportCallback: this._passportCallback,
			generateAccessToken: this._generateAccessToken,
			generateRequestToken: this._generateRequestToken,
			generateRefeshToken: this._generateRefeshToken,
			requestTokenCallback: this._requestTokenCallback,
			verify: this._verify
		}
	},

	strategy: function () {
		var verify = this._config.hook.verify(this._config);
		return new JwtStrategy(this._config, verify);
	},

	authenticate: function (opts) {
		var self = this;

		opts = opts || {session: false};

		return function (req, res, next) {
			if (self._config.ignoreRequestTokenUrl.indexOf(req.path) === -1) {
				switch (req.path) {
					case self._config.requestTokenEndpoint:
						req.authenticate = self._requestAuthInfo(req);
						self._config.hook.generateRequestToken(req, res, next, self._config);
						break;
					case self._config.refreshTokenEndpoint:
						passport.authenticate(
							'passport-auth-jwt', opts,
							self._config.hook.generateRefeshToken(req, res, next, self._config)
						)(req, res, next);
						break;
					case self._config.tokenEndpoint:
						passport.authenticate(
							'passport-auth-jwt', opts,
							self._config.hook.generateAccessToken(req, res, next, self._config)
						)(req, res, next);
						break;
					default:
						passport.authenticate(
							'passport-auth-jwt', opts, self._config.hook.passportCallback(req, res, next)
						)(req, res, next);
				}
			} else {
				next();
			}
		}
	},

	_verify: function () {
		return function (req, payload, done) {
			console.log('[Passport Auth JWT] "hook.verify" must be a function in the options of Passport Auth JWT.');
			done(null, false);
		}
	},

	_generateRequestToken: function (req, secret, callback) {
		console.log('[Passport Auth JWT] "hook.generateRequestToken" must be a function in the options of Passport Auth JWT');
		callback();
	},

	_passportCallback: function (req, res, next) {
		return function (err, user, info) {
			if (user) {
				req.user = user;
				next();
			} else {
				next(err || info);
			}
		}
	},

	_requestAuthInfo: function (req) {
		var clientIdParams = this._config['clientId'];
		var auth = req.headers['authorization'];
		var clientId = (req.headers[clientIdParams] || req.query[clientIdParams]);

		if (auth) {
			var tmp = auth.split(' ');

			if (tmp[0] === 'Basic') {
				var buf = new Buffer(tmp[1], 'base64');
				var auth_plain = buf.toString();
				var creds = auth_plain.split(':');

				return {client: creds[0], secret: creds[1]};
			} else {
				return {};
			}
		} else {
			return {client: clientId};
		}
	},

	_generateRefeshToken: function () {
		console.log('[Passport Auth JWT] "hook.generateRefeshToken," must be a function in the options of Passport Auth JWT');
	},

	_generateAccessToken: function () {
		console.log('[Passport Auth JWT] "hook.generateAccessToken" must be a function in the options of Passport Auth JWT');
	},

	_requestTokenCallback: function (req, res) {
		return function () {
			res.send({
				message: '[Passport Auth JWT] "hook.requestTokenCallback" must be a function in the options of Passport Auth JWT'
			});
		}
	}
};

module.exports = PassportAuthJWT;
exports.error = error;