using System;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.IO;
namespace ClientSideSocket
{
    class ClientClass
    {
        public static Socket socket;
        public static byte[] getbyte = new byte[1024];
        public static byte[] setbyte = new byte[1024];

        public const int sPort = 123;



        [STAThread]
        static void Main(string[] args)
        {
            Random rnd = new Random();
            string sendstring = null;
            string getstring = null;
            ulong random_prime, random_integer, myPublic_key, your_Public_key, myPrivacy_key, last_key;
            random_prime = 1073676287;
            random_integer = 8824;
            myPrivacy_key = (ulong)rnd.Next(1,100);

            int count = 0;
            String FilePath = "C:/Users/user/Desktop/password.txt";
            FileInfo fi = new FileInfo(FilePath);


            IPAddress serverIP = IPAddress.Parse("129.254.220.222");
            IPEndPoint serverEndPoint = new IPEndPoint(serverIP, sPort);

            socket = new Socket(
              AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);

            Console.WriteLine("------------------------------");
            Console.WriteLine(" 서버로 접속합니다.[엔터를 입력하세요] ");
            Console.WriteLine("------------------------------");
            Console.ReadLine();

            socket.Connect(serverEndPoint);

            if (socket.Connected)
            {
                Console.WriteLine(">>연결 되었습니다.(데이터를 입력하세요)");
            }

            while (count == 0)
            {
                getbyte = new byte[1024];
                if (!fi.Exists) //파일 존재하지 않을시
                {
                    Console.WriteLine("파일 비존재!");
                    int getValueLength = 0;
                    setbyte = Encoding.Default.GetBytes(random_prime.ToString());
                    socket.Send(setbyte, 0, setbyte.Length, SocketFlags.None);   //prime 보냄
                    Console.WriteLine("Prime value : " + Encoding.Default.GetString(setbyte) + " & " + setbyte.Length);
                    Console.Write(">>");


                    setbyte = Encoding.Default.GetBytes(random_integer.ToString());      //integer 보냄
                    socket.Send(setbyte, 0, setbyte.Length, SocketFlags.None);
                    Console.WriteLine("Integer value : "+Encoding.Default.GetString(setbyte) + " & " + setbyte.Length);

                    socket.Receive(getbyte, 0, getbyte.Length, SocketFlags.None);   //상대방의 공개키 가져옴
                    getValueLength = byteArrayDefrag(getbyte);
                    your_Public_key = Convert.ToUInt64(Encoding.Default.GetString(getbyte, 0, getValueLength + 1));
                    Console.WriteLine("Your public key : " + your_Public_key + " & " + getValueLength);
                    //Console.WriteLine(your_Public_key);
                    myPublic_key = power(random_integer, myPrivacy_key, random_prime);
                    setbyte = Encoding.Default.GetBytes(myPublic_key.ToString());      //나의 공개키 보냄
                    socket.Send(setbyte, 0, setbyte.Length, SocketFlags.None);
                    Console.WriteLine("my public key : " + Encoding.Default.GetString(setbyte) + " & " + setbyte.Length);


                    last_key = power(your_Public_key, myPrivacy_key, random_prime);

                   
                    System.IO.File.WriteAllText(FilePath, last_key.ToString(), Encoding.Default);
                    Console.WriteLine("최종키 is " + last_key);


                    count = 1;

                }
                else    //파일 존재할때 
                {
                    TextReader tr = fi.OpenText();
                    string abc = tr.ReadToEnd();
                    Console.WriteLine("파일 존재!");
                    byte[] cba = Encoding.Default.GetBytes(abc);
                    string result = Convert.ToBase64String(cba);        //Base64인코딩을 통한 데이터 전송
                    setbyte = Encoding.Default.GetBytes(result);
                    Console.WriteLine("여기 값은 무엇인가: " + result);

                    socket.Send(setbyte, 0, setbyte.Length, SocketFlags.None);
                    Console.WriteLine(Encoding.Default.GetString(setbyte));
                    count++;
                }
            }
        }

        public static int byteArrayDefrag(byte[] sData)
        {
            int endLength = 0;

            for (int i = 0; i < sData.Length; i++)
            {
                if ((byte)sData[i] != (byte)0)
                {
                    endLength = i;
                }
            }

            return endLength;
        }

        static public ulong power(ulong a, ulong b, ulong mod)
        {
            ulong t;
            if (b == 1)
                return a;
            t = power(a, b / 2, mod);
            if (b % 2 == 0)
                return (t * t) % mod;
            else
                return (((t * t) % mod) * a) % mod;
        }
    }
}

