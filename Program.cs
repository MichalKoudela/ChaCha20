using System.Text;
using System.IO;

Console.WriteLine("Chcete spustit test vector či šifrování ze souboru? (t/s)");
string volba = Console.ReadLine();
if (volba == "t")
{
    ChaCha cha = new ChaCha(1, volba);
    string testPT = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    byte[] pTArray = Encoding.UTF8.GetBytes(testPT);
    byte[] vysledek = cha.encrypt(pTArray);
    Console.WriteLine("Ciphertext:");
    foreach (var element in vysledek)
    {
        Console.Write($"{element:X2}" + " ");
    }
}
else if (volba == "s")
{
    Console.WriteLine("Zadejte counter");
    uint counter = 0;
    if (!uint.TryParse(Console.ReadLine(), out counter))
    {
        Console.WriteLine("Neplatný vstup pro counter.");
        return;
    }
    Console.WriteLine("Zadejte nonce soubor:");
    string nonceSoubor = Console.ReadLine();
    if (File.Exists(nonceSoubor))
    {
        long delkaSouboruNonce = new System.IO.FileInfo(nonceSoubor).Length;
        if (delkaSouboruNonce == 12)
        {
            Console.WriteLine("Zadejte key soubor:");
            string keySoubor = Console.ReadLine();
            if (File.Exists(keySoubor))
            {
                long delkaSouboruKlic = new System.IO.FileInfo(keySoubor).Length;
                if (delkaSouboruKlic == 32)
                {
                    Console.WriteLine("Zadejte název souboru pro šifrování:");
                    string nazevSouboru = Console.ReadLine();
                    if (File.Exists(nazevSouboru))
                    {
                        byte[] klic = File.ReadAllBytes(keySoubor);

                        byte[] cast1 = new byte[4];
                        cast1[0] = klic[0];
                        cast1[1] = klic[1];
                        cast1[2] = klic[2];
                        cast1[3] = klic[3];
                        uint pole1 = BitConverter.ToUInt32(cast1, 0);

                        byte[] cast2 = new byte[4];
                        cast2[0] = klic[4];
                        cast2[1] = klic[5];
                        cast2[2] = klic[6];
                        cast2[3] = klic[7];
                        uint pole2 = BitConverter.ToUInt32(cast2, 0);

                        byte[] cast3 = new byte[4];
                        cast3[0] = klic[8];
                        cast3[1] = klic[9];
                        cast3[2] = klic[10];
                        cast3[3] = klic[11];
                        uint pole3 = BitConverter.ToUInt32(cast3, 0);

                        byte[] cast4 = new byte[4];
                        cast4[0] = klic[12];
                        cast4[1] = klic[13];
                        cast4[2] = klic[14];
                        cast4[3] = klic[15];
                        uint pole4 = BitConverter.ToUInt32(cast4, 0);

                        byte[] cast5 = new byte[4];
                        cast5[0] = klic[16];
                        cast5[1] = klic[17];
                        cast5[2] = klic[18];
                        cast5[3] = klic[19];
                        uint pole5 = BitConverter.ToUInt32(cast5, 0);

                        byte[] cast6 = new byte[4];
                        cast6[0] = klic[20];
                        cast6[1] = klic[21];
                        cast6[2] = klic[22];
                        cast6[3] = klic[23];
                        uint pole6 = BitConverter.ToUInt32(cast6, 0);

                        byte[] cast7 = new byte[4];
                        cast7[0] = klic[24];
                        cast7[1] = klic[25];
                        cast7[2] = klic[26];
                        cast7[3] = klic[27];
                        uint pole7 = BitConverter.ToUInt32(cast7, 0);

                        byte[] cast8 = new byte[4];
                        cast8[0] = klic[28];
                        cast8[1] = klic[29];
                        cast8[2] = klic[30];
                        cast8[3] = klic[31];
                        uint pole8 = BitConverter.ToUInt32(cast8, 0);

                        byte[] nonce = File.ReadAllBytes(nonceSoubor);

                        byte[] cast9 = new byte[4];
                        cast9[0] = nonce[0];
                        cast9[1] = nonce[1];
                        cast9[2] = nonce[2];
                        cast9[3] = nonce[3];
                        uint nonce1 = BitConverter.ToUInt32(cast9, 0);

                        byte[] cast10 = new byte[4];
                        cast10[0] = nonce[4];
                        cast10[1] = nonce[5];
                        cast10[2] = nonce[6];
                        cast10[3] = nonce[7];
                        uint nonce2 = BitConverter.ToUInt32(cast10, 0);

                        byte[] cast11 = new byte[4];
                        cast11[0] = nonce[8];
                        cast11[1] = nonce[9];
                        cast11[2] = nonce[10];
                        cast11[3] = nonce[11];
                        uint nonce3 = BitConverter.ToUInt32(cast11, 0);

                        ChaCha cha = new ChaCha(counter, volba, pole1, pole2, pole3, pole4, pole5, pole6, pole7, pole8, nonce1, nonce2, nonce3);
                        string text = File.ReadAllText(nazevSouboru);
                        byte[] pTArray = Encoding.UTF8.GetBytes(text);
                        byte[] cTArray = cha.encrypt(pTArray);
                        Console.WriteLine("Ciphertext:");
                        foreach (var element in cTArray)
                        {
                            Console.Write($"{element:X2}" + " ");
                        }
                    }
                    else
                    {
                        Console.WriteLine("Soubor pro šifrování neexistuje.");
                        return;
                    }
                }
                else
                {
                    Console.WriteLine("Neplatná délka souboru key.");
                    return;
                }
            }
        }
        else
        {
            Console.WriteLine("Neplatná délka souboru nonce.");
            return;
        }
    }

}
else
{
    Console.WriteLine("Neplatná volba.");
    return;
}
class ChaCha
{
    uint[,] pole = new uint[4, 4];
    List<byte> keyStream = new List<byte>();
    uint counter = 1;
    public ChaCha(uint c,
                string variantion,
                uint key1 = 0x03020100,
                uint key2 = 0x07060504,
                uint key3 = 0x0b0a0908,
                uint key4 = 0x0f0e0d0c,
                uint key5 = 0x13121110,
                uint key6 = 0x17161514,
                uint key7 = 0x1b1a1918,
                uint key8 = 0x1f1e1d1c,
                uint nonce1 = 0x00000000,
                uint nonce2 = 0x4a000000,
                uint nonce3 = 0x00000000)
    {
        this.counter = c;
        this.pole[0, 0] = 0x61707865;
        this.pole[0, 1] = 0x3320646e;
        this.pole[0, 2] = 0x79622d32;
        this.pole[0, 3] = 0x6b206574;
        this.pole[1, 0] = key1;
        this.pole[1, 1] = key2;
        this.pole[1, 2] = key3;
        this.pole[1, 3] = key4;
        this.pole[2, 0] = key5;
        this.pole[2, 1] = key6;
        this.pole[2, 2] = key7;
        this.pole[2, 3] = key8;
        this.pole[3, 0] = counter;
        this.pole[3, 1] = nonce1;
        this.pole[3, 2] = nonce2;
        this.pole[3, 3] = nonce3;
    }
    public byte[] encrypt(byte[] PT)
    {
        int pocetOpakovani = (PT.Length * 8) / 512;
        for (int m = 0; m < pocetOpakovani + 1; m++)
        {
            generatePartOfKey();
        }
        byte[] CT = new byte[PT.Length];
        for (int i = 0; i < PT.Length; i++)
        {
            CT[i] = (byte)(keyStream.ElementAt(i) ^ PT[i]);
        }
        return CT;
    }
    public byte[] decrypt(byte[] CT, byte[] Key)
    {
        byte[] pTArray = new byte[CT.Length];
        for (int i = 0; i < CT.Length; i++)
        {
            pTArray[i] = (byte)(Key[i] ^ CT[i]);
        }
        return pTArray;
    }
    void generatePartOfKey()
    {
        // Vytvoření kopie pole
        uint[,] copy = (uint[,])pole.Clone();
        // 20 kol
        for (int i = 0; i < 10; i++)
        {
            QuarterRound(0, 0, 1, 0, 2, 0, 3, 0);
            QuarterRound(0, 1, 1, 1, 2, 1, 3, 1);
            QuarterRound(0, 2, 1, 2, 2, 2, 3, 2);
            QuarterRound(0, 3, 1, 3, 2, 3, 3, 3);
            QuarterRound(0, 0, 1, 1, 2, 2, 3, 3);
            QuarterRound(0, 1, 1, 2, 2, 3, 3, 0);
            QuarterRound(0, 2, 1, 3, 2, 0, 3, 1);
            QuarterRound(0, 3, 1, 0, 2, 1, 3, 2);
        }
        // Přičtení původního pole
        for (int i = 0; i < 4; i++)
        {
            for (int j = 0; j < 4; j++)
            {
                pole[i, j] += copy[i, j];
            }
        }
        // Konvertuje na byty a potom zapíše do keystream
        for (int i = 0; i < 4; i++)
        {
            for (int j = 0; j < 4; j++)
            {
                byte[] bytes = BitConverter.GetBytes(pole[i, j]);
                keyStream.AddRange(bytes);
            }
        }
        pole = copy;
        counter++;
        pole[3, 0] = counter;
    }

    void QuarterRound(int Ax, int Ay, int Bx, int By, int Cx, int Cy, int Dx, int Dy)
    {
        pole[Ax, Ay] += pole[Bx, By];
        pole[Dx, Dy] ^= pole[Ax, Ay];
        pole[Dx, Dy] = (pole[Dx, Dy] << 16) | (pole[Dx, Dy] >> (32 - 16));

        pole[Cx, Cy] += pole[Dx, Dy];
        pole[Bx, By] ^= pole[Cx, Cy];
        pole[Bx, By] = (pole[Bx, By] << 12) | (pole[Bx, By] >> (32 - 12));

        pole[Ax, Ay] += pole[Bx, By];
        pole[Dx, Dy] ^= pole[Ax, Ay];
        pole[Dx, Dy] = (pole[Dx, Dy] << 8) | (pole[Dx, Dy] >> (32 - 8));

        pole[Cx, Cy] += pole[Dx, Dy];
        pole[Bx, By] ^= pole[Cx, Cy];
        pole[Bx, By] = (pole[Bx, By] << 7) | (pole[Bx, By] >> (32 - 7));
    }
}