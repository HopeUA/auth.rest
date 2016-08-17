import Moment from 'moment';

module.exports = () => {
    return async (request, response, next) => {
        const app = request.app;
        const User = app.models.User;
        const Token = app.models.Token;

        const accessToken = request.headers.authorization ? request.headers.authorization.replace('Bearer ', '') : null;

        if (accessToken === null) {
            request.user = getAnonymousUser();
        } else {
            try {
                request.user = User.toPublic(await getCurrentUser());
            } catch (error) {
                return next(error);
            }
        }

        function getAnonymousUser() {
            return new User({
                id: '',
                firstName: "Anonymous",
                email: "guest@hope.ua",
                permissions: []
            });
        }

        async function getCurrentUser() {
            const token = await Token.findOne({
                where: { accessToken }
            });

            if (token === null) {
                const error = new Error('Token is invalid');
                error.statusCode = 401;
                throw error;
            }

            const expire = Moment(token.expire);
            if (!expire.isValid() || expire.isBefore(Moment())) {
                const error = new Error('Token is expired');
                error.statusCode = 401;
                throw error;
            }

            const user = await User.findById(token.userId);
            if (user === null) {
                const error = new Error('User not found');
                error.statusCode = 401;
                throw error;
            }

            return user;
        }

        next();
    }
};
