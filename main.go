package main

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
)

const (
	azureADOpenIDConfigURL = "https://login.microsoftonline.com/{tenantId}/v2.0/.well-known/openid-configuration"
	tenantID               = "YOUR APP TENANT ID"
	jwtKey                 = "YOUR APP SECRET KEY VALUE" // Reemplaza con tu propia clave secreta generada
	clientID               = "YOUR APP CLIENT ID"
)

// Se definen dos estructuras: TokenValidator y TokenValidatorConfig. La estructura TokenValidator contiene un campo Config que es un puntero a la estructura TokenValidatorConfig. La estructura TokenValidatorConfig contiene los campos necesarios para configurar el validador de tokens, incluyendo la URL de configuración de OpenID de Azure AD, el ID del inquilino y el ID de cliente.
type TokenValidator struct {
	Config *TokenValidatorConfig
}

type TokenValidatorConfig struct {
	AzureADOpenIDConfigURL string
	TenantID               string
	ClientID               string
}

// Se definen las estructuras AzureADOpenIDConfig, JWK y JWKS. Estas estructuras se utilizan para analizar y almacenar la configuración de OpenID de Azure AD y las claves JWK asociadas.
type AzureADOpenIDConfig struct {
	Issuer  string `json:"issuer"`
	JwksURI string `json:"jwks_uri"`
}

type JWK struct {
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type JWKS struct {
	Keys []JWK `json:"keys"`
}

// Se define la estructura TokenValidationResult que representa el resultado de la validación de un token. Contiene un campo Valid para indicar si el token es válido y un campo Error que almacena un posible error en caso de que la validación falle.
type TokenValidationResult struct {
	Valid bool
	Error error
}

// La función main es el punto de entrada del programa. Aquí se crea una instancia del validador de tokens utilizando la función NewTokenValidator y se configuran los parámetros necesarios. Luego se crea un enrutador Gin y se registra el controlador ValidateTokenHandler para la ruta "/validate-token". Finalmente, se inicia el servidor web utilizando el método Run del enrutador Gin.
func main() {
	tokenValidator := NewTokenValidator(&TokenValidatorConfig{
		AzureADOpenIDConfigURL: azureADOpenIDConfigURL,
		TenantID:               tenantID,
		ClientID:               clientID,
	})

	router := gin.Default()
	router.POST("/validate-token", tokenValidator.ValidateTokenHandler)

	log.Fatal(router.Run(":8000"))
}

// La función NewTokenValidator es un constructor para crear una nueva instancia de TokenValidator. Recibe un parámetro config que es un puntero a una estructura TokenValidatorConfig y devuelve un puntero a una instancia de TokenValidator configurada con el valor proporcionado.
func NewTokenValidator(config *TokenValidatorConfig) *TokenValidator {
	return &TokenValidator{
		Config: config,
	}
}

// La función ValidateTokenHandler es el controlador para la ruta "/validate-token". Recibe un contexto Gin (c) que contiene la solicitud y la respuesta HTTP. En esta función, se obtiene el token de autorización del encabezado de la solicitud y se valida su formato. Luego, se obtiene la configuración de OpenID de Azure AD llamando a la función getAzureADOpenIDConfig. Después, se obtienen las claves JWK de Azure AD llamando a la función getAzureADJWKS. Estas claves se imprimen en la consola para fines de depuración. A continuación, se realiza la validación del token llamando a la función validateToken. Si el token no es válido, se devuelve un error en la respuesta HTTP. Si el token es válido, se devuelve un mensaje de éxito en la respuesta HTTP.
func (v *TokenValidator) ValidateTokenHandler(c *gin.Context) {
	tokenString := c.GetHeader("Authorization")
	if tokenString == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Token de autorización faltante"})
		return
	}

	tokenParts := strings.Split(tokenString, "Bearer ")
	if len(tokenParts) != 2 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Formato de token inválido"})
		return
	}

	// fmt.Println("Token recibido:", tokenString)

	tokenString = tokenParts[1]

	oidcConfig, err := v.getAzureADOpenIDConfig()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error al obtener la configuración de OpenID de Azure AD"})
		return
	}

	jwks, err := v.getAzureADJWKS(oidcConfig.JwksURI)
	fmt.Println("Claves JWK obtenidas:")
	for _, key := range jwks.Keys {
		fmt.Println("Kid:", key.Kid)
		fmt.Println("N:", key.N)
		fmt.Println("E:", key.E)
		fmt.Println("--------------")
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error al obtener las claves JWK de Azure AD"})
		return
	}

	tokenValidationResult := v.validateToken(tokenString, jwks, oidcConfig.Issuer)
	if !tokenValidationResult.Valid {
		c.JSON(http.StatusUnauthorized, gin.H{"error": tokenValidationResult.Error.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Token válido"})
}

// La función getAzureADOpenIDConfig se encarga de obtener la configuración de OpenID de Azure AD. Construye la URL de la configuración reemplazando {tenantId} con el ID del inquilino configurado. Luego, realiza una solicitud HTTP GET a esa URL y verifica el código de estado de la respuesta. Si la respuesta es exitosa (código 200), se lee el cuerpo de la respuesta y se decodifica en una estructura AzureADOpenIDConfig utilizando json.Unmarshal. Finalmente, devuelve un puntero a la configuración obtenida.
func (v *TokenValidator) getAzureADOpenIDConfig() (*AzureADOpenIDConfig, error) {
	azureADOpenIDConfigURL := strings.ReplaceAll(v.Config.AzureADOpenIDConfigURL, "{tenantId}", v.Config.TenantID)

	resp, err := http.Get(azureADOpenIDConfigURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Error al obtener la configuración de OpenID de Azure AD. Código de estado: %d", resp.StatusCode)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var config AzureADOpenIDConfig
	err = json.Unmarshal(body, &config)
	if err != nil {
		return nil, err
	}

	return &config, nil
}

// La función getAzureADJWKS se encarga de obtener las claves JWK de Azure AD. Realiza una solicitud HTTP GET a la URL proporcionada y verifica el código de estado de la respuesta. Si la respuesta es exitosa, se lee el cuerpo de la respuesta y se decodifica en una estructura JWKS utilizando json.Unmarshal. Finalmente, devuelve un puntero a las claves JWK obtenidas.
func (v *TokenValidator) getAzureADJWKS(url string) (*JWKS, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Error al obtener las claves JWK de Azure AD. Código de estado: %d", resp.StatusCode)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var jwks JWKS
	err = json.Unmarshal(body, &jwks)
	if err != nil {
		return nil, err
	}

	return &jwks, nil
}

// La función validateToken se encarga de validar el token. Primero, se realiza el análisis del token utilizando jwt.Parse. En la función de análisis, se busca la clave JWK correspondiente al valor kid en el encabezado del token. Se decodifican los valores n y e de la clave JWK y se construye una instancia de rsa.PublicKey. Luego, se devuelve la clave pública para su uso en la validación del token.

// Si el análisis y la validación del token tienen éxito, se verifica que el emisor del token coincida con la configuración proporcionada. Si todas las validaciones son exitosas, se devuelve un resultado de validación de token válido.
func (v *TokenValidator) validateToken(tokenString string, jwks *JWKS, issuer string) TokenValidationResult {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, fmt.Errorf("Clave 'kid' no encontrada")
		}

		var jwk *JWK
		for _, key := range jwks.Keys {
			if key.Kid == kid {
				jwk = &key
				break
			}
		}

		if jwk == nil {
			return nil, fmt.Errorf("Clave JWK no encontrada")
		}

		nBytes, err := base64.RawURLEncoding.DecodeString(jwk.N)
		if err != nil {
			return nil, fmt.Errorf("Error al decodificar el valor 'n' de la clave JWK")
		}

		eBytes, err := base64.RawURLEncoding.DecodeString(jwk.E)
		if err != nil {
			return nil, fmt.Errorf("Error al decodificar el valor 'e' de la clave JWK")
		}

		n := big.NewInt(0).SetBytes(nBytes)
		e := big.NewInt(0).SetBytes(eBytes)

		pubKey := &rsa.PublicKey{
			N: n,
			E: int(e.Int64()),
		}

		return pubKey, nil
	})

	if err != nil {
		return TokenValidationResult{
			Valid: false,
			Error: err,
		}
	}

	if !token.Valid {
		return TokenValidationResult{
			Valid: false,
			Error: nil,
		}
	}

	claims := token.Claims.(jwt.MapClaims)
	exp := claims["exp"].(float64)
	expirationTime := time.Unix(int64(exp), 0)
	if time.Now().UTC().After(expirationTime) {
		return TokenValidationResult{
			Valid: false,
			Error: fmt.Errorf("Token expirado"),
		}
	}

	audience := claims["aud"].(string)
	if audience != v.Config.ClientID {
		return TokenValidationResult{
			Valid: false,
			Error: fmt.Errorf("Token no válido para la audiencia especificada"),
		}
	}

	if issuer != claims["iss"].(string) {
		return TokenValidationResult{
			Valid: false,
			Error: fmt.Errorf("Token no válido para el emisor especificado"),
		}
	}

	tenant := claims["tid"].(string)
	if tenant != v.Config.TenantID {
		return TokenValidationResult{
			Valid: false,
			Error: fmt.Errorf("Token no válido para el inquilino especificado"),
		}
	}

	return TokenValidationResult{
		Valid: true,
		Error: nil,
	}
}
