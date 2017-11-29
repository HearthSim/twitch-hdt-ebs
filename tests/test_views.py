def test_config_view(client):
	response = client.post("/config/")

	assert response.status_code == 403


def test_setup_view(client):
	response = client.post("/setup/")

	assert response.status_code == 403


def test_send_view(client):
	response = client.post("/send/")

	assert response.status_code == 401
