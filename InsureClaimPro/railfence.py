def rail_encrypt(text, rails):
    if rails <= 1:
        return text
    
    fence = [[] for _ in range(rails)]
    rail = 0
    direction = 1
    
    for char in text:
        fence[rail].append(char)
        rail += direction
        if rail == rails - 1 or rail == 0:
            direction = -direction
    
    encrypted = ''.join([''.join(row) for row in fence])
    return encrypted


def rail_decrypt(cipher, rails):
    if rails <= 1:
        return cipher
    
    n = len(cipher)
    fence = [['' for _ in range(n)] for _ in range(rails)]
    
    rail = 0
    direction = 1
    for i in range(n):
        fence[rail][i] = '*'
        rail += direction
        if rail == rails - 1 or rail == 0:
            direction = -direction
    
    index = 0
    for i in range(rails):
        for j in range(n):
            if fence[i][j] == '*' and index < n:
                fence[i][j] = cipher[index]
                index += 1
    
    result = []
    rail = 0
    direction = 1
    for i in range(n):
        result.append(fence[rail][i])
        rail += direction
        if rail == rails - 1 or rail == 0:
            direction = -direction
    
    return ''.join(result)


def encrypt_file_content(content, rails=3):
    import base64
    if isinstance(content, bytes):
        encoded = base64.b64encode(content).decode('utf-8')
    else:
        encoded = base64.b64encode(content.encode('utf-8')).decode('utf-8')
    encrypted = rail_encrypt(encoded, rails)
    return encrypted


def decrypt_file_content(encrypted_content, rails=3):
    import base64
    decrypted = rail_decrypt(encrypted_content, rails)
    decoded = base64.b64decode(decrypted)
    return decoded
