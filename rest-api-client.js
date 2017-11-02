const axios = require('axios');

class RestApiClient {
	constructor(baseUrl) {
		this.client = axios.create({
			baseURL: baseUrl,
			timeout: 5000,
			headers: {
				'Content-Type': 'application/json'
			},
			transformRequest: [(data, headers) => {
				headers.Authorization = `Bearer ${this.getToken()}`;

				return data;
			}]
		});
	}

	setToken(token) {
		this.token = token;
	}

	getToken() {
		return this.token;
	}

	currentUser() {
		return this.client.get('/user/current');
	}
}

function createRestApiClient(baseUrl) {
	return new RestApiClient(baseUrl);
}

module.exports = createRestApiClient;