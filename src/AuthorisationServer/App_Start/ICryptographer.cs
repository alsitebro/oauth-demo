namespace AuthorisationServer
{
    public interface ICryptographer
    {
        string Encrypt(string key, string input);
        string Decrypt(string key, string input);
        string Hash(string input);
    }
}