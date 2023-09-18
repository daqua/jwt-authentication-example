import com.ecolytiq.jwt.Utils
import org.junit.jupiter.api.Test
import java.io.File

class JWTExampleTest {

    companion object {
        val resources = File("src/test/resources/").toPath()
    }

    @Test
    fun createJWSExample() {
        // load private key
        val privateSenderKey = Utils.readECKey(resources.resolve("customer-ec-private-key.pem"))

        // customize the token content
        // identifies corresponding public key
        val keyId = "customer-ec-key-2023"
        // identifies the issuer
        val issuer = "customer-example-bank.com"
        // identifies the account Id
        val accountId = "TestAccountId"
        // defines the token lifetime, eg. 5 min
        val expirationAfterSeconds = 5 * 60

        // create token
        val token = Utils.createECToken(
            keyId = keyId,
            issuer = issuer,
            expirationAfterSeconds = expirationAfterSeconds,
            accountId = accountId,
            privateECKey = privateSenderKey,
        )

        println("Example Token:")
        println(token)
        println("-------------------------")
        println("Call: https://whitelabel-example.customer-example-bank.com?code=$token")
        println("-------------------------")
        println("Start Validation")

        // start validating
        val signedToken = Utils.parseSignedToken(token)

        // load public key based of key id. in this example we keep it simple, because we have just one public key
        // val keyIdFromToken = Utils.extractKeyId(signedToken)
        val publicSenderKey = Utils.readECKey(resources.resolve("customer-ec-public-key.pem"))
        // load expected content to validate token
        val expectedIssuer = issuer

        // check signature
        // check expiration time
        // check issuer
        // check existing accountId
        val valid = Utils.verifyToken(token = signedToken, publicKey = publicSenderKey, expectedIssuer = expectedIssuer)
        println("Valid Token? $valid")

        println("AccountId = ${Utils.extractAccountId(signedToken)}")
    }
}
