
def test_register_user(client):
    response = client.post(
        "/auth/register",
        json={
            "username": "testuser",
            "email": "testuser@example.com",
            "password": "TestPassword123!",
        },
    )

    assert response.status_code == 201

    data = response.json()

    assert data["username"] == "testuser"
    assert data["email"] == "testuser@example.com"
    assert data["role"] == "viewer"
    assert "password" not in data
    assert "password_hash" not in data

def test_login_success(client):
    # First, register a test user
    client.post(
        "/auth/register",
        json={
            "username": "loginuser",
            "email": "loginuser@example.com",
            "password": "LoginPassword123!",
        },
    )

    # Now, log in with the same credentials
    response = client.post(
        "/auth/login",
        data={
            "username": "loginuser",
            "password": "LoginPassword123!",
        },
    )

    assert response.status_code == 200

    data = response.json()

    assert "access_token" in data
    assert data["token_type"] == "bearer"

def test_login_wrong_password(client):
    # Register a user first
    client.post(
        "/auth/register",
        json={
            "username": "wrongpassuser",
            "email": "wrongpass@example.com",
            "password": "CorrectPassword123!",
        },
    )

    # Try to log in with an incorrect password
    response = client.post(
        "/auth/login",
        data={
            "username": "wrongpassuser",
            "password": "WrongPassword123!",
        },
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid username or password"

def test_me_without_token(client):
    response = client.get("/auth/me")

    assert response.status_code == 401
    assert response.json()["detail"] == "Not authenticated"

def test_me_with_valid_token(client):
    # Register a user
    client.post(
        "/auth/register",
        json={
            "username": "profileuser",
            "email": "profileuser@example.com",
            "password": "ProfilePassword123!",
        },
    )

    # Log in and get an access token
    login_response = client.post(
        "/auth/login",
        data={
            "username": "profileuser",
            "password": "ProfilePassword123!",
        },
    )

    token = login_response.json()["access_token"]

    # Use the token to access the protected profile
    response = client.get(
        "/auth/me",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200
    assert response.json()["username"] == "profileuser"
    assert response.json()["role"] == "viewer"
