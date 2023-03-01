using Microsoft.AspNetCore.Mvc;
using Shyfr.Models;
using System.Diagnostics;
using System.Text;

using System.Security.Cryptography;
namespace Shyfr.Controllers
{
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;

        public HomeController(ILogger<HomeController> logger)
        {
            _logger = logger;
        }

        public IActionResult vizhener()
        {
            return View();
        }
        public IActionResult transpon()
        {
            return View();
        }
        public IActionResult morze()
        {
            return View();
        }

        public IActionResult dvcode()
        {
            return View();
        }

        public IActionResult cezar()
        {
            return View();
        }

        public IActionResult rot1()
        {
            return View();
        }

        public IActionResult Index()
        {
            return View();
        }

        public IActionResult Privacy()
        {
            return View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }

        [HttpPost]
        public ActionResult cezar(string submit, string clearText, string cipherText)
        {
            switch (submit)
            {
                case "Encrypt":
                    TempData["EncryptedTextCeazar"] = this.EncryptCeazar(clearText);
                    break;
                case "Decrypt":
                    TempData["DecryptedTextCeazar"] = this.DecryptCeazar(cipherText);
                    break;
            }

            return View();
        }

        private string EncryptCeazar(string clearText)
        {
            string m = clearText;

            int nomer; // Номер в алфавите
            int d; // Смещение
            string s; //Результат
            int j; // Переменная для циклов

            char[] massage = m.ToCharArray(); // Превращаем строку в массив символов. 'я' ,'ю' ,'э' ,'ь' ,'ы' ,'ъ' ,'щ' ,'ш' ,'ч' ,'ц' ,'х' ,'ф' ,'у' ,'т' ,'с' ,'р' ,'п' ,'о' ,'н' ,'м' ,'л' ,'к' ,'й' ,'и' ,'з' ,'ж' ,'ё' ,'е' ,'д' ,'г' ,'в' ,'б' ,'а'

            char[] alfavit = { 'а', 'б', 'в', 'г', 'д', 'е', 'ё', 'ж', 'з', 'и', 'й', 'к', 'л', 'м', 'н', 'о', 'п', 'р', 'с', 'т', 'у', 'ф', 'х', 'ц', 'ч', 'ш', 'щ', 'ъ', 'ы', 'ь', 'э', 'ю', 'я' };

            // Перебираем каждый символ сообщения
            for (int i = 0; i < massage.Length; i++)
            {
                // Ищем индекс буквы
                for (j = 0; j < alfavit.Length; j++)
                {
                    if (massage[i] == alfavit[j])
                    {
                        break;
                    }
                }

                if (j != 33) // Если j равно 33, значит символ не из алфавита
                {
                    nomer = j; // Индекс буквы
                    d = nomer + 13; // Делаем смещение

                    // Проверяем, чтобы не вышли за пределы алфавита
                    if (d > 32)
                    {
                        d = d - 33;
                    }

                    massage[i] = alfavit[d]; // Меняем букву
                }
            }

            clearText = new string(massage);

            return clearText;
        }

        private string DecryptCeazar(string cipherText)
        {
            string m = cipherText;

            int nomer; // Номер в алфавите
            int d; // Смещение
            string s; //Результат
            int j; // Переменная для циклов

            char[] massage = m.ToCharArray(); // Превращаем строку в массив символов. 'я' ,'ю' ,'э' ,'ь' ,'ы' ,'ъ' ,'щ' ,'ш' ,'ч' ,'ц' ,'х' ,'ф' ,'у' ,'т' ,'с' ,'р' ,'п' ,'о' ,'н' ,'м' ,'л' ,'к' ,'й' ,'и' ,'з' ,'ж' ,'ё' ,'е' ,'д' ,'г' ,'в' ,'б' ,'а'

            char[] alfavit = { 'я', 'ю', 'э', 'ь', 'ы', 'ъ', 'щ', 'ш', 'ч', 'ц', 'х', 'ф', 'у', 'т', 'с', 'р', 'п', 'о', 'н', 'м', 'л', 'к', 'й', 'и', 'з', 'ж', 'ё', 'е', 'д', 'г', 'в', 'б', 'а' };

            // Перебираем каждый символ сообщения
            for (int i = 0; i < massage.Length; i++)
            {
                // Ищем индекс буквы
                for (j = 0; j < alfavit.Length; j++)
                {
                    if (massage[i] == alfavit[j])
                    {
                        break;
                    }
                }

                if (j != 33) // Если j равно 33, значит символ не из алфавита
                {
                    nomer = j; // Индекс буквы
                    d = nomer + 13; // Делаем смещение

                    // Проверяем, чтобы не вышли за пределы алфавита
                    if (d > 32)
                    {
                        d = d - 33;
                    }

                    massage[i] = alfavit[d]; // Меняем букву
                }
            }

            cipherText = new string(massage);

            return cipherText;
        }
        [HttpPost]
        public ActionResult transpon(string submit, string clearText, string cipherText)
        {
            switch (submit)
            {
                case "Encrypt":
                    TempData["EncryptedText"] = this.Encrypt(clearText);
                    break;
                case "Decrypt":
                    TempData["DecryptedText"] = this.Decrypt(cipherText);
                    break;
            }

            return View();
        }

        private string Encrypt(string clearText)
        {
            string encryptionKey = "MAKV2SPBNI99212";
            byte[] clearBytes = Encoding.Unicode.GetBytes(clearText);
            using (Aes encryptor = Aes.Create())
            {
                Rfc2898DeriveBytes pdb = new Rfc2898DeriveBytes(encryptionKey, new byte[] { 0x49, 0x76, 0x61, 0x6e, 0x20, 0x4d, 0x65, 0x64, 0x76, 0x65, 0x64, 0x65, 0x76 });
                encryptor.Key = pdb.GetBytes(32);
                encryptor.IV = pdb.GetBytes(16);
                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, encryptor.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(clearBytes, 0, clearBytes.Length);
                        cs.Close();
                    }
                    clearText = Convert.ToBase64String(ms.ToArray());
                }
            }

            return clearText;
        }

        private string Decrypt(string cipherText)
        {
            string encryptionKey = "MAKV2SPBNI99212";
            byte[] cipherBytes = Convert.FromBase64String(cipherText);
            using (Aes encryptor = Aes.Create())
            {
                Rfc2898DeriveBytes pdb = new Rfc2898DeriveBytes(encryptionKey, new byte[] { 0x49, 0x76, 0x61, 0x6e, 0x20, 0x4d, 0x65, 0x64, 0x76, 0x65, 0x64, 0x65, 0x76 });
                encryptor.Key = pdb.GetBytes(32);
                encryptor.IV = pdb.GetBytes(16);
                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, encryptor.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(cipherBytes, 0, cipherBytes.Length);
                        cs.Close();
                    }
                    cipherText = Encoding.Unicode.GetString(ms.ToArray());
                }
            }

            return cipherText;
        }

        //vizhener
        [HttpPost]
        public ActionResult vizhener(string submit, string clearText, string cipherText, string password)
        {
            var cipher = new VigenereCipher("АБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ");
            switch (submit)
            {
                case "Encrypt":
                    TempData["EncryptedText"] = cipher.Encrypt(clearText.ToUpper(), password.ToUpper());
                    break;
                case "Decrypt":
                    TempData["DecryptedText"] = cipher.Decrypt(cipherText.ToUpper(), password.ToUpper());
                    break;
            }

            return View();
        }

        public class VigenereCipher
        {
            const string defaultAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
            readonly string letters;

            public VigenereCipher(string alphabet = null)
            {
                letters = string.IsNullOrEmpty(alphabet) ? defaultAlphabet : alphabet;
            }

            //генерация повторяющегося пароля
            private string GetRepeatKey(string s, int n)
            {
                var p = s;
                while (p.Length < n)
                {
                    p += p;
                }

                return p.Substring(0, n);
            }

            private string Vigenere(string text, string password, bool encrypting = true)
            {
                var gamma = GetRepeatKey(password, text.Length);
                var retValue = "";
                var q = letters.Length;

                for (int i = 0; i < text.Length; i++)
                {
                    var letterIndex = letters.IndexOf(text[i]);
                    var codeIndex = letters.IndexOf(gamma[i]);
                    if (letterIndex < 0)
                    {
                        //если буква не найдена, добавляем её в исходном виде
                        retValue += text[i].ToString();
                    }
                    else
                    {
                        retValue += letters[(q + letterIndex + ((encrypting ? 1 : -1) * codeIndex)) % q].ToString();
                    }
                }

                return retValue;
            }

            //шифрование текста
            public string Encrypt(string plainMessage, string password)
                => Vigenere(plainMessage, password);

            //дешифрование текста
            public string Decrypt(string encryptedMessage, string password)
                => Vigenere(encryptedMessage, password, false);
        }

        [HttpPost]
        public ActionResult rot1(string submit, string clearText, string cipherText)
        {
            switch (submit)
            {
                case "Encrypt":
                    TempData["EncryptedTextCeazar"] = this.Encryptrot(clearText);
                    break;
                case "Decrypt":
                    TempData["DecryptedTextCeazar"] = this.Decryptrot(cipherText);
                    break;
            }

            return View();
        }

        private string Encryptrot(string clearText)
        {
            string m = clearText;

            int nomer; // Номер в алфавите
            int d; // Смещение
            string s; //Результат
            int j; // Переменная для циклов

            char[] massage = m.ToCharArray(); // Превращаем строку в массив символов. 'я' ,'ю' ,'э' ,'ь' ,'ы' ,'ъ' ,'щ' ,'ш' ,'ч' ,'ц' ,'х' ,'ф' ,'у' ,'т' ,'с' ,'р' ,'п' ,'о' ,'н' ,'м' ,'л' ,'к' ,'й' ,'и' ,'з' ,'ж' ,'ё' ,'е' ,'д' ,'г' ,'в' ,'б' ,'а'

            char[] alfavit = { 'а', 'б', 'в', 'г', 'д', 'е', 'ё', 'ж', 'з', 'и', 'й', 'к', 'л', 'м', 'н', 'о', 'п', 'р', 'с', 'т', 'у', 'ф', 'х', 'ц', 'ч', 'ш', 'щ', 'ъ', 'ы', 'ь', 'э', 'ю', 'я' };

            // Перебираем каждый символ сообщения
            for (int i = 0; i < massage.Length; i++)
            {
                // Ищем индекс буквы
                for (j = 0; j < alfavit.Length; j++)
                {
                    if (massage[i] == alfavit[j])
                    {
                        break;
                    }
                }

                if (j != 33) // Если j равно 33, значит символ не из алфавита
                {
                    nomer = j; // Индекс буквы
                    d = nomer + 1; // Делаем смещение

                    // Проверяем, чтобы не вышли за пределы алфавита
                    if (d > 32)
                    {
                        d = d - 33;
                    }

                    massage[i] = alfavit[d]; // Меняем букву
                }
            }

            clearText = new string(massage);

            return clearText;
        }

        private string Decryptrot(string cipherText)
        {
            string m = cipherText;

            int nomer; // Номер в алфавите
            int d; // Смещение
            string s; //Результат
            int j; // Переменная для циклов

            char[] massage = m.ToCharArray(); // Превращаем строку в массив символов. 'я' ,'ю' ,'э' ,'ь' ,'ы' ,'ъ' ,'щ' ,'ш' ,'ч' ,'ц' ,'х' ,'ф' ,'у' ,'т' ,'с' ,'р' ,'п' ,'о' ,'н' ,'м' ,'л' ,'к' ,'й' ,'и' ,'з' ,'ж' ,'ё' ,'е' ,'д' ,'г' ,'в' ,'б' ,'а'

            char[] alfavit = { 'я', 'ю', 'э', 'ь', 'ы', 'ъ', 'щ', 'ш', 'ч', 'ц', 'х', 'ф', 'у', 'т', 'с', 'р', 'п', 'о', 'н', 'м', 'л', 'к', 'й', 'и', 'з', 'ж', 'ё', 'е', 'д', 'г', 'в', 'б', 'а' };

            // Перебираем каждый символ сообщения
            for (int i = 0; i < massage.Length; i++)
            {
                // Ищем индекс буквы
                for (j = 0; j < alfavit.Length; j++)
                {
                    if (massage[i] == alfavit[j])
                    {
                        break;
                    }
                }

                if (j != 33) // Если j равно 33, значит символ не из алфавита
                {
                    nomer = j; // Индекс буквы
                    d = nomer + 1; // Делаем смещение

                    // Проверяем, чтобы не вышли за пределы алфавита
                    if (d > 32)
                    {
                        d = d - 33;
                    }

                    massage[i] = alfavit[d]; // Меняем букву
                }
            }

            cipherText = new string(massage);

            return cipherText;
        }
    }
}