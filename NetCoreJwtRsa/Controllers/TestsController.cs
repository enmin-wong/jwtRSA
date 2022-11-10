using Microsoft.AspNetCore.Mvc;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using static Microsoft.AspNetCore.Http.StatusCodes;

namespace NetCoreJwtRsa.Controllers
{
    [Route("api/v1/[controller]")]
    public class TestsController : ControllerBase
    {
        private readonly IJwtHandler _jwtHandler;
        public TestsController(IJwtHandler jwtHandler)
        {
            _jwtHandler = jwtHandler;
        }

        [HttpPost]
        [Route("token")]
        [ProducesResponseType(typeof(string), Status200OK)]
        public IActionResult GenerateJwt()
        {

            var claims = new JwtCustomClaims
            {
                name = "Vynn",
                preferred_username = "Durano",
                email = "whatever@email.com"
            };

            var jwt = _jwtHandler.CreateToken(claims);

            var link = _jwtHandler.GenerateLink(jwt.Token);

            return Ok(jwt);
        }

        [HttpPost]
        [Route("token/validate")]
        [ProducesResponseType(typeof(string), Status200OK)]
        public IActionResult ValidateJwt([FromBody] string token)
        {

            if (_jwtHandler.ValidateToken(token))
            {
                var handler = new JwtSecurityTokenHandler();
                var jwtToken = handler.ReadToken(token) as JwtSecurityToken;

                var claims = new JwtCustomClaims
                {
                    name = jwtToken.Claims.First(claim => claim.Type == "name").Value,
                    preferred_username = jwtToken.Claims.First(claim => claim.Type == "preferred_username").Value,
                    email = jwtToken.Claims.First(claim => claim.Type == "email").Value
                };

                return Ok(claims);
            }

            return BadRequest("Token is invalid.");
        }
    }
}