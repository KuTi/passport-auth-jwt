/**
 * Error
 */

module.exports = function () {
	return function (done) {
		var error = new Error("Can't verify JWT");
		return done(error, false);
	}
};