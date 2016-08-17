import _bcrypt from 'bcrypt';
import Promise from 'bluebird';

const Bcrypt = Promise.promisifyAll(_bcrypt);

export async function Hash(password) {
    return await Bcrypt.hashAsync(password, 11);
}

export async function Compare(password, hash) {
    return await Bcrypt.compareAsync(password, hash);
}
