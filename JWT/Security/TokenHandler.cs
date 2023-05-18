using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Text;
using System;
using Microsoft.Extensions.Configuration;
using System.Security.Cryptography;

namespace JWT.Security
{
    public static class TokenHandler
    {
        public static Token CreateToken(IConfiguration configuration)
        {
            Token token = new Token();

            SymmetricSecurityKey key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration["Token:SecurityKey"]));

            SigningCredentials credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            token.Expiration = DateTime.UtcNow.AddMinutes(Convert.ToInt16(configuration["Token:Expiration"]));

            JwtSecurityToken jwtSecurityToken = new(
                issuer: configuration["Token:Issuer"],
                               audience: configuration["Token:Audience"],
                                              expires: token.Expiration,
                                              notBefore: DateTime.Now,
                                                             signingCredentials: credentials
                                                                            );

            JwtSecurityTokenHandler tokenHandler = new();

            token.AccessToken = tokenHandler.WriteToken(jwtSecurityToken);

            byte[] refreshToken = new byte[32];

            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(refreshToken);
                token.RefreshToken = Convert.ToBase64String(refreshToken);
            }

            return token;
        }

    }
}
