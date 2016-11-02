import ShortId from 'shortid';
import Moment from 'moment';
import Prepare from 'common/utils/prepareModel';
import { Compare } from 'common/utils/bcrypt';

module.exports = (Token) => {
    Prepare(Token, { clean: true });

    Token.remoteMethod('auth', {
        http: { verb: 'post', path: '/', status: 201 },
        accepts: [
            {
                arg: 'grant_type',
                type: 'String',
                required: true,
                http: { source: 'form' }
            },
            {
                arg: 'request',
                type: 'object',
                http: { source: 'req' }
            }
        ],
        returns: {
            type: 'Object',
            root: true
        }
    });

    Token.auth = async (grantType, request) => {
        switch (grantType) {
            case 'password':
                return passwordGrantType(request.body);
            case 'refresh_token':
                return refreshTokenGrantType(request.body);
            default:
                throw new Error(`Grant type "${grantType}" not supported`);
        }
    };

    async function passwordGrantType(data) {
        const User = Token.app.models.AppUser;
        const { username, password } = data;

        if (typeof username !== 'string' || username.length === 0) {
            throw new Error('Username must be defined');
        }
        if (typeof password !== 'string' || password.length === 0) {
            throw new Error('Password must be defined');
        }

        // Get User by email
        // TODO logging
        const user = await User.findOne({
            where: {
                email: username
            }
        });
        if (!user) {
            throw new Error('Email or password incorrect');
        }

        // Validate password
        const valid = await Compare(password, user.passwordHash);
        if (!valid) {
            throw new Error('Email or password incorrect');
        }

        // Generate tokens
        const accessToken = [];
        for (let i = 0; i < 5; i++) {
            accessToken.push(ShortId.generate());
        }
        const refreshToken = [];
        for (let i = 0; i < 5; i++) {
            refreshToken.push(ShortId.generate());
        }

        // Save tokens
        const token = await Token.create({
            accessToken: accessToken.join(''),
            refreshToken: refreshToken.join(''),
            userId: user.id,
            expire: Moment().add(10, 'm').toDate()
        });

        return token;
    }

    async function refreshTokenGrantType(data) {
        const User = Token.app.models.AppUser;
        const refreshToken = data.refresh_token;

        // Get token
        const token = await Token.findOne({
            where: {
                refreshToken
            }
        });
        if (!token) {
            throw new Error('Refresh token error');
        }

        // Get user
        const user = await User.findOne({
            where: {
                id: token.userId
            }
        });
        if (!user) {
            throw new Error('User associated with token is blocked');
        }

        // Generate new token
        const accessToken = [];
        for (let i = 0; i < 5; i++) {
            accessToken.push(ShortId.generate());
        }

        token.accessToken = accessToken.join('');
        token.expire = Moment().add(10, 'm').toDate();
        token.save();

        return token;
    }
};
