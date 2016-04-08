/**
 * Error
 */

module.exports = function (done) {
	var error = new Error("Can't verify JWT");
	return done(error, false);
};