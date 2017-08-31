using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.Writer;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using de4dot.blocks.cflow;
using de4dot.blocks;
using System.Reflection;
using System.Security.Cryptography;
using System.IO.Compression;

namespace MindSystemDeobfuscatorBase
{
    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();
            this.pictureBox1.AllowDrop = true;
        }
        private void TextBox1DragEnter(object sender, DragEventArgs e)
        {
            if (e.Data.GetDataPresent(DataFormats.FileDrop))
            {
                e.Effect = DragDropEffects.Copy;
            }
            else
            {
                e.Effect = DragDropEffects.None;
            }
        }
        string DirectoryName = "";
        string ExePath = "";
        public static int DeobedString = 0;
        private void TextBox1DragDrop(object sender, DragEventArgs e)
        {
            try
            {
                Array arrayyy = (Array)e.Data.GetData(DataFormats.FileDrop);
                if (arrayyy != null)
                {
                    string text = arrayyy.GetValue(0).ToString();
                    int num = text.LastIndexOf(".", StringComparison.Ordinal);
                    if (num != -1)
                    {
                        string text2 = text.Substring(num);
                        text2 = text2.ToLower();
                        if (text2 == ".exe" || text2 == ".dll")
                        {
                            Activate();
                            ExePath = text;
                            label2.Text = "Status : Exe Loaded";
                            int num2 = text.LastIndexOf("\\", StringComparison.Ordinal);
                            if (num2 != -1)
                            {
                                DirectoryName = text.Remove(num2, text.Length - num2);
                            }
                            if (DirectoryName.Length == 2)
                            {
                                DirectoryName += "\\";
                            }
                        }
                    }
                }
            }
            catch
            {
            }
            ModuleDefMD module = ModuleDefMD.Load(ExePath);
            CFLow(module);
            if (DetectDotWall(module))
            {
                label5.Text = "Obfuscator : " + obfuscator;
                label4.Text = "Decryption Method token : " + "0x" + decryptiontoken.ToString("X");
                CFLow(module);
                if (DetectResource(module))
                {
                    ResourceDecryptor(module);
                }
                GetRes2(module);
                CheckProxy(module);
                label7.Text = "Amount of proxies fixed : " + proxyfixed;
                DeobfuscatorBase(module);
                RemoveAntiDebug(module);
                CFLow(module);
                label6.Text = "Resource Name : " + resourcename;
                label2.Text = "Status : Saving Exe";
                string filename = DirectoryName + "\\" + Path.GetFileNameWithoutExtension(ExePath) + "-Decrypted" + Path.GetExtension(ExePath);
                var opts = new ModuleWriterOptions(module);
                opts.Logger = DummyLogger.NoThrowInstance;
                opts.MetaDataOptions.Flags = MetaDataFlags.PreserveAll;
                var writerOptions = new NativeModuleWriterOptions(module);
                writerOptions.MetaDataOptions.Flags = MetaDataFlags.PreserveAll;
                writerOptions.Logger = DummyLogger.NoThrowInstance;
                if (module.IsILOnly)
                {
                    module.Write(filename, opts);
                }
                else
                {
                    module.NativeWrite(filename, writerOptions);
                }
                label2.Text = "Status : Success ! ";
                label3.Text = "Amount of strings decrypted : " + DeobedString;
                label2.ForeColor = Color.Green;
            }
            else
            {
                DialogResult result = MessageBox.Show("DotWall Not detected, do you want to unpack?", "Info", MessageBoxButtons.YesNo, MessageBoxIcon.Information);
                if (result == DialogResult.Yes)
                {
                    label5.Text = "Obfuscator : " + obfuscator;
                    label4.Text = "Decryption Method token : " + "0x" + decryptiontoken.ToString("X");
                    CFLow(module);
                    if (DetectResource(module))
                    {
                        ResourceDecryptor(module);
                    }
                    GetRes2(module);
                    CheckProxy(module);
                    DeobfuscatorBase(module);
                    RemoveAntiDebug(module);
                    CFLow(module);
                    label6.Text = "Resource Name : " + resourcename;
                    label2.Text = "Status : Saving Exe";
                    string filename = DirectoryName + "\\" + Path.GetFileNameWithoutExtension(ExePath) + "-Decrypted" + Path.GetExtension(ExePath);
                    var opts = new ModuleWriterOptions(module);
                    opts.Logger = DummyLogger.NoThrowInstance;
                    opts.MetaDataOptions.Flags = MetaDataFlags.PreserveAll;
                    var writerOptions = new NativeModuleWriterOptions(module);
                    writerOptions.MetaDataOptions.Flags = MetaDataFlags.PreserveAll;
                    writerOptions.Logger = DummyLogger.NoThrowInstance;
                    if (module.IsILOnly)
                    {
                        module.Write(filename, opts);
                    }
                    else
                    {
                        module.NativeWrite(filename, writerOptions);
                    }
                    label2.Text = "Status : Success ! ";
                    label3.Text = "Amount of strings decrypted : " + DeobedString;
                    label2.ForeColor = Color.Green;
                }
                else
                {

                }
            }

        }
        public static int proxyfixed = 0;
        public static void RemoveAntiDebug(ModuleDefMD module)
        {
            string typename = "";
            string methodname = "";
            foreach (TypeDef type in module.Types)
            {
                foreach (MethodDef method in type.Methods)
                {
                    if (method.HasBody == false)
                        continue;
                    if (method.Body.Instructions.Count < 15)
                    {
                        for (int i = 0; i < method.Body.Instructions.Count; i++)
                        {
                            if (method.Body.Instructions[i].OpCode == OpCodes.Ldstr && method.Body.Instructions[i].Operand.ToString().Contains("Debugger detected !"))
                            {
                                typename = method.DeclaringType.Name;
                                methodname = method.Name;
                                goto remover;
                            }
                        }
                    }
                }
            }
            remover:
            MethodDef methodd = module.EntryPoint;
            for (int i = 0; i < methodd.Body.Instructions.Count; i++)
            {
                if (methodd.Body.Instructions[i].OpCode == OpCodes.Call && methodd.Body.Instructions[i].Operand.ToString().Contains(typename) && methodd.Body.Instructions[i].Operand.ToString().Contains(methodname))
                {
                    methodd.Body.Instructions.RemoveAt(i);
                    return;
                }
            }
        }
        public static void FindReference(ModuleDefMD module, string methname, Instruction[] inst)
        {
            foreach (TypeDef type in module.Types)
            {
                foreach (MethodDef method in type.Methods)
                {
                    if (method.HasBody == false)
                        continue;
                    for (int i = 0; i < method.Body.Instructions.Count; i++)
                    {
                        if (method.Body.Instructions[i].OpCode == OpCodes.Call && method.Body.Instructions[i].Operand.ToString().Contains(methname) && method.Body.Instructions[i - 1].IsLdcI4())
                        {
                            Emulate(module, method.Body.Instructions[i - 1].GetLdcI4Value(), inst, methname);
                        }
                        else if (method.Body.Instructions[i].OpCode == OpCodes.Callvirt && method.Body.Instructions[i].Operand.ToString().Contains(methname) && method.Body.Instructions[i - 1].IsLdcI4())
                        {
                            Emulate(module, method.Body.Instructions[i - 1].GetLdcI4Value(), inst, methname);
                            //    method.Body.Instructions[i].Operand = operand;
                            //  method.Body.Instructions.RemoveAt(i - 1);
                        }
                    }


                }
            }
        }

        public static void Emulate(ModuleDefMD module, int arg, Instruction[] inst, string methname)
        {
            foreach (TypeDef type in module.Types)
            {
                foreach (MethodDef method in type.Methods)
                {
                    if (method.HasBody == false)
                        continue;
                    if (method.Name.Equals(methname))
                    {
                        for (int i = 0; i < method.Body.Instructions.Count; i++)
                        {
                            if (method.Body.Instructions[0].OpCode == OpCodes.Ldarg && method.Body.Instructions[1].IsLdcI4() && method.Body.Instructions[2].OpCode == OpCodes.Xor)
                            {
                                string waye = method.Name;
                                Instruction[] final = inst;
                                int casee = arg ^ method.Body.Instructions[1].GetLdcI4Value();
                                Instruction instt = final[casee];
                                uint offset = instt.Offset;
                                for (int z = 0; z < method.Body.Instructions.Count; z++)
                                {
                                    if (method.Body.Instructions[z].Offset == offset)
                                    {
                                        for (int y = z; y < method.Body.Instructions.Count; y++)
                                        {
                                            if (method.Body.Instructions[y].OpCode == OpCodes.Call || method.Body.Instructions[y].OpCode == OpCodes.Callvirt)
                                            {
                                                object operand = method.Body.Instructions[y].Operand;
                                                ReplaceCall2(operand, method.Name, module, arg);
                                                proxyfixed++;
                                                return;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        public static void ReplaceCall(object operand, string methname, ModuleDefMD module)
        {
            foreach (TypeDef type in module.Types)
            {
                foreach (MethodDef method in type.Methods)
                {
                    if (method.HasBody == false)
                        continue;
                    for (int i = 0; i < method.Body.Instructions.Count; i++)
                    {

                        if (method.Body.Instructions[i].OpCode == OpCodes.Call && method.Body.Instructions[i].Operand.ToString().Contains(methname) && method.Body.Instructions[i - 1].IsLdcI4())
                        {
                            method.Body.Instructions[i].Operand = operand;
                            method.Body.Instructions.RemoveAt(i - 1);
                        }
                        else if (method.Body.Instructions[i].OpCode == OpCodes.Callvirt && method.Body.Instructions[i].Operand.ToString().Contains(methname) && method.Body.Instructions[i - 1].IsLdcI4())
                        {
                            method.Body.Instructions[i].Operand = operand;
                            method.Body.Instructions.RemoveAt(i - 1);
                        }
                    }
                }
            }
        }
        public static void ReplaceCall2(object operand, string methname, ModuleDefMD module, int arg)
        {
            foreach (TypeDef type in module.Types)
            {
                foreach (MethodDef method in type.Methods)
                {
                    if (method.HasBody == false)
                        continue;
                    for (int i = 0; i < method.Body.Instructions.Count; i++)
                    {

                        if (method.Body.Instructions[i].OpCode == OpCodes.Call && method.Body.Instructions[i].Operand.ToString().Contains(methname) && method.Body.Instructions[i - 1].IsLdcI4() && method.Body.Instructions[i - 1].GetLdcI4Value() == arg)
                        {
                            method.Body.Instructions[i].Operand = operand;
                            method.Body.Instructions.RemoveAt(i - 1);
                            return;
                        }
                        else if (method.Body.Instructions[i].OpCode == OpCodes.Callvirt && method.Body.Instructions[i].Operand.ToString().Contains(methname) && method.Body.Instructions[i - 1].IsLdcI4() && method.Body.Instructions[i - 1].GetLdcI4Value() == arg)
                        {
                            method.Body.Instructions[i].Operand = operand;
                            method.Body.Instructions.RemoveAt(i - 1);
                            return;
                        }
                    }
                }
            }
        }
        public static void CheckProxy(ModuleDefMD module)
        {
            foreach (TypeDef type in module.Types)
            {
                foreach (MethodDef method in type.Methods)
                {
                    if (method.HasBody == false)
                        continue;
                    if (method.Body.Instructions.Count < 17)
                    {
                        if (method.Body.Instructions[0].OpCode == OpCodes.Ldarg && method.Body.Instructions[1].IsLdcI4() && method.Body.Instructions[2].OpCode == OpCodes.Xor)
                        {
                            for (int i = 0; i < method.Body.Instructions.Count; i++)
                            {
                                if (method.Body.Instructions[i].OpCode == OpCodes.Switch)
                                {
                                    Instruction[] switches = method.Body.Instructions[i].Operand as Instruction[];
                                    for (int z = 0; z < switches.Length; z++)
                                    {
                                        if (switches.Length == 1)
                                        {
                                            for (int y = 0; y < method.Body.Instructions.Count; y++)
                                            {
                                                if (method.Body.Instructions[y].OpCode == OpCodes.Call)
                                                {
                                                    object operand = method.Body.Instructions[y].Operand;
                                                    string methname = method.Name;
                                                    ReplaceCall(operand, methname, module);
                                                    proxyfixed++;
                                                }
                                                else if (method.Body.Instructions[y].OpCode == OpCodes.Callvirt)
                                                {
                                                    object operand = method.Body.Instructions[y].Operand;
                                                    string methname = method.Name;
                                                    ReplaceCall(operand, methname, module);
                                                    proxyfixed++;
                                                }
                                            }
                                        }
                                        else
                                        {
                                            FindReference(module, method.Name, switches);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        public static int sc9YTrbT(byte[] O19b9ILM)
        {
            if (KluwmDOK(O19b9ILM) == 9)
            {
                return (int)O19b9ILM[5] | (int)O19b9ILM[6] << 8 | (int)O19b9ILM[7] << 16 | (int)O19b9ILM[8] << 24;
            }
            return (int)O19b9ILM[2];
        }
        private static int KluwmDOK(byte[] Fe5V6rah)
        {
            if ((Fe5V6rah[0] & 2) != 2)
            {
                return 3;
            }
            return 9;
        }

        public static byte[] AI5Yp3i7(byte[] byte_0)
        {
            int num = sc9YTrbT(byte_0);
            int num2 = KluwmDOK(byte_0);
            int i = 0;
            uint num3 = 1u;
            byte[] array = new byte[num];
            int[] array2 = new int[4096];
            byte[] array3 = new byte[4096];
            int num4 = num - 6 - 4 - 1;
            int j = -1;
            uint num5 = 0u;
            int num6 = byte_0[0] >> 2 & 3;
            if (num6 != 1 && num6 != 3)
            {
                throw new ArgumentException("C# version only supports level 1 and 3");
            }
            if ((byte_0[0] & 1) != 1)
            {
                byte[] array4 = new byte[num];
                Array.Copy(byte_0, KluwmDOK(byte_0), array4, 0, num);
                return array4;
            }
            while (true)
            {
                if (num3 == 1u)
                {
                    num3 = (uint)((int)byte_0[num2] | (int)byte_0[num2 + 1] << 8 | (int)byte_0[num2 + 2] << 16 | (int)byte_0[num2 + 3] << 24);
                    num2 += 4;
                    if (i <= num4)
                    {
                        if (num6 == 1)
                        {
                            num5 = (uint)((int)byte_0[num2] | (int)byte_0[num2 + 1] << 8 | (int)byte_0[num2 + 2] << 16);
                        }
                        else
                        {
                            num5 = (uint)((int)byte_0[num2] | (int)byte_0[num2 + 1] << 8 | (int)byte_0[num2 + 2] << 16 | (int)byte_0[num2 + 3] << 24);
                        }
                    }
                }
                if ((num3 & 1u) == 1u)
                {
                    num3 >>= 1;
                    uint num8;
                    uint num9;
                    if (num6 == 1)
                    {
                        int num7 = (int)num5 >> 4 & 4095;
                        num8 = (uint)array2[num7];
                        if ((num5 & 15u) != 0u)
                        {
                            num9 = (num5 & 15u) + 2u;
                            num2 += 2;
                        }
                        else
                        {
                            num9 = (uint)byte_0[num2 + 2];
                            num2 += 3;
                        }
                    }
                    else
                    {
                        uint num10;
                        if ((num5 & 3u) == 0u)
                        {
                            num10 = (num5 & 255u) >> 2;
                            num9 = 3u;
                            num2++;
                        }
                        else
                        {
                            if ((num5 & 2u) == 0u)
                            {
                                num10 = (num5 & 65535u) >> 2;
                                num9 = 3u;
                                num2 += 2;
                            }
                            else
                            {
                                if ((num5 & 1u) == 0u)
                                {
                                    num10 = (num5 & 65535u) >> 6;
                                    num9 = (num5 >> 2 & 15u) + 3u;
                                    num2 += 2;
                                }
                                else
                                {
                                    if ((num5 & 127u) != 3u)
                                    {
                                        num10 = (num5 >> 7 & 131071u);
                                        num9 = (num5 >> 2 & 31u) + 2u;
                                        num2 += 3;
                                    }
                                    else
                                    {
                                        num10 = num5 >> 15;
                                        num9 = (num5 >> 7 & 255u) + 3u;
                                        num2 += 4;
                                    }
                                }
                            }
                        }
                        num8 = (uint)((long)i - (long)((ulong)num10));
                    }
                    array[i] = array[(int)((UIntPtr)num8)];
                    array[i + 1] = array[(int)((UIntPtr)(num8 + 1u))];
                    array[i + 2] = array[(int)((UIntPtr)(num8 + 2u))];
                    int num11 = 3;
                    while ((long)num11 < (long)((ulong)num9))
                    {
                        array[i + num11] = array[(int)checked((IntPtr)unchecked((ulong)num8 + (ulong)((long)num11)))];
                        num11++;
                    }
                    i += (int)num9;
                    if (num6 == 1)
                    {
                        num5 = (uint)((int)array[j + 1] | (int)array[j + 2] << 8 | (int)array[j + 3] << 16);
                        while ((long)j < (long)i - (long)((ulong)num9))
                        {
                            j++;
                            int num7 = (int)((num5 >> 12 ^ num5) & 4095u);
                            array2[num7] = j;
                            array3[num7] = 1;
                            num5 = (uint)((ulong)(num5 >> 8 & 65535u) | (ulong)((long)((long)array[j + 3] << 16)));
                        }
                        num5 = (uint)((int)byte_0[num2] | (int)byte_0[num2 + 1] << 8 | (int)byte_0[num2 + 2] << 16);
                    }
                    else
                    {
                        num5 = (uint)((int)byte_0[num2] | (int)byte_0[num2 + 1] << 8 | (int)byte_0[num2 + 2] << 16 | (int)byte_0[num2 + 3] << 24);
                    }
                    j = i - 1;
                }
                else
                {
                    if (i > num4)
                    {
                        break;
                    }
                    array[i] = byte_0[num2];
                    i++;
                    num2++;
                    num3 >>= 1;
                    if (num6 == 1)
                    {
                        while (j < i - 3)
                        {
                            j++;
                            int num12 = (int)array[j] | (int)array[j + 1] << 8 | (int)array[j + 2] << 16;
                            int num7 = (num12 >> 12 ^ num12) & 4095;
                            array2[num7] = j;
                            array3[num7] = 1;
                        }
                        num5 = (uint)((ulong)(num5 >> 8 & 65535u) | (ulong)((long)((long)byte_0[num2 + 2] << 16)));
                    }
                    else
                    {
                        num5 = (uint)((ulong)(num5 >> 8 & 65535u) | (ulong)((long)((long)byte_0[num2 + 2] << 16)) | (ulong)((long)((long)byte_0[num2 + 3] << 24)));
                    }
                }
            }
            while (i <= num - 1)
            {
                if (num3 == 1u)
                {
                    num2 += 4;
                    num3 = 2147483648u;
                }
                array[i] = byte_0[num2];
                i++;
                num2++;
                num3 >>= 1;
            }
            return array;
        }
        private static readonly byte[] yfb3dkj1 = new byte[]
{
   38,
   220,
   255,
   0,
   173,
   237,
   122,
   238,
   197,
   254,
   7,
   175,
   77,
   8,
   34,
   60
};

        public static byte[] uxl3MqLX(byte[] TljaXm0G, string etPA1i9i)
        {
            try
            {
                Rijndael rijndael = Rijndael.Create();
                Rfc2898DeriveBytes rfc2898DeriveBytes = new Rfc2898DeriveBytes(etPA1i9i, yfb3dkj1);
                rijndael.Key = rfc2898DeriveBytes.GetBytes(32);
                rijndael.IV = rfc2898DeriveBytes.GetBytes(16);
                MemoryStream memoryStream = new MemoryStream();
                CryptoStream cryptoStream = new CryptoStream(memoryStream, rijndael.CreateDecryptor(), CryptoStreamMode.Write);
                cryptoStream.Write(TljaXm0G, 0, TljaXm0G.Length);
                cryptoStream.Close();
                return memoryStream.ToArray();
            }
            catch
            {
                return null;
            }

        }

        public static void ResourceDecryptor(ModuleDefMD module)
        {
            Stream manifestResourceStream = GetRes(module);
            if (manifestResourceStream != null)
            {
                BinaryReader binaryReader = new BinaryReader(manifestResourceStream);
                byte[] array = new byte[manifestResourceStream.Length];
                binaryReader.Read(array, 0, array.Length);
                byte[] arrayy = uxl3MqLX(array, key);
                if (arrayy == null)
                {

                }
                else
                {
                    Assembly asm = Assembly.Load(AI5Yp3i7(arrayy));
                    Module[] modules = asm.GetModules();
                    module.Resources.Clear();
                    Module[] array4 = modules;
                    for (int l = 0; l < array4.Length; l++)
                    {
                        Module module2 = array4[l];
                        string[] manifestResourceNames = module2.Assembly.GetManifestResourceNames();
                        string[] array5 = manifestResourceNames;
                        for (int m = 0; m < array5.Length; m++)
                        {
                            string text = array5[m];
                            Stream manifestResourceStream1 = module2.Assembly.GetManifestResourceStream(text);
                            using (MemoryStream memoryStream2 = new MemoryStream())
                            {
                                manifestResourceStream1.CopyTo(memoryStream2);
                                byte[] data = memoryStream2.ToArray();
                                module.Resources.Add(new EmbeddedResource(text, data, ManifestResourceAttributes.Public));
                            }
                        }
                    }
                }

            }
        }

        public static MethodDef resmethod = null;
        public static string resdecryptname = "";
        public static bool DetectResource(ModuleDefMD module)
        {
            foreach (TypeDef type in module.Types)
            {
                foreach (MethodDef method in type.Methods)
                {
                    if (method.HasBody == false)
                        continue;
                    if (method.Body.Instructions.Count > 25)
                    {
                        for (int i = 0; i < method.Body.Instructions.Count; i++)
                        {
                            if (method.Body.Instructions[0].OpCode == OpCodes.Ldsfld && method.Body.Instructions[1].OpCode == OpCodes.Brtrue_S)
                            {
                                if (method.Body.Instructions[i].OpCode == OpCodes.Call && method.Body.Instructions[i + 1].OpCode == OpCodes.Ldstr && method.Body.Instructions[i].Operand.ToString().Contains("System.Reflection.Assembly"))
                                {
                                    resmethod = method;
                                    resdecryptname = method.Name;
                                    for (int z = 0; z < method.Body.Instructions.Count; z++)
                                    {
                                        if (method.Body.Instructions[z].OpCode == OpCodes.Call && method.Body.Instructions[z].Operand.ToString().ToLower().Contains("byte[]") && method.Body.Instructions[z - 1].OpCode == OpCodes.Ldstr)
                                        {
                                            key = method.Body.Instructions[z - 1].Operand.ToString();
                                            goto finished;
                                        }
                                    }
                                    finished:
                                    return true;
                                }
                            }
                        }

                    }
                }
            }
            return false;
        }
        public static string key = "";
        public static int decryptiontoken = 0;
        public static string obfuscator = "";
        public static string decryptionname = "";
        public static string decryptionmethodname = "";
        public static string resourcename = "";
        public static string proxymethodname = "";
        public static void GetProxyDecryptionMethod(ModuleDefMD module)
        {
            foreach (TypeDef type in module.Types)
            {
                foreach (MethodDef method in type.Methods)
                {
                    if (method.HasBody == false)
                        continue;
                    if (method.Body.Instructions.Count < 10)
                    {
                        for (int i = 0; i < method.Body.Instructions.Count; i++)
                        {
                            if (method.Body.Instructions[i].OpCode == OpCodes.Call && method.Body.Instructions[i].Operand.ToString().Contains(decryptionmethodname) && method.Body.Instructions[i].Operand.ToString().Contains(decryptionname))
                            {
                                proxymethodname = method.Name;
                            }
                        }
                    }
                }
            }
        }
       
        public static bool DetectDotWall(ModuleDefMD module)
        {
            foreach (TypeDef type in module.Types)
            {
                foreach (MethodDef method in type.Methods)
                {
                    if (method.HasBody == false)
                        continue;
                    if (method.Body.Instructions.Count < 20)
                    {
                        if (method.Body.Instructions[0].OpCode == OpCodes.Ldsfld && method.Body.Instructions[1].OpCode == OpCodes.Newobj)
                        {
                            for (int i = 0; i < method.Body.Instructions.Count; i++)
                            {
                                if (method.Body.Instructions[i].OpCode == OpCodes.Call && method.Body.Instructions[i].Operand.ToString().Contains("BinaryReader") || method.Body.Instructions[i].OpCode == OpCodes.Callvirt && method.Body.Instructions[i].Operand.ToString().Contains("BinaryReader"))
                                {
                                    decryptionname = method.DeclaringType.Name;
                                    decryptionmethodname = method.Name;
                                    decryptiontoken = method.MDToken.ToInt32();
                                    obfuscator = "DotWall";
                                    foreach (MethodDef method2 in method.DeclaringType.Methods)
                                    {
                                        if (method2.Name.Contains(".cctor"))
                                        {
                                            for (int z = 0; z < method2.Body.Instructions.Count; z++)
                                            {
                                                if (method2.Body.Instructions[z].OpCode == OpCodes.Call)
                                                {
                                                    if (method2.Body.Instructions[z + 1].OpCode == OpCodes.Ldstr)
                                                    {
                                                        resourcename = (string)method2.Body.Instructions[z + 1].Operand;
                                                      
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    GetProxyDecryptionMethod(module);
                                    return true;
                                }
                            }

                        }
                    }
                }
            }
            return false;
        }
        public static void CFLow(ModuleDefMD module)
        {
            foreach(TypeDef type in module.Types)
            {
                foreach(MethodDef method in type.Methods)
                {
                    if (method.HasBody == false)
                        continue;
                    BlocksCflowDeobfuscator blocksCflowDeobfuscator = new BlocksCflowDeobfuscator();
                    Blocks blocks = new Blocks(method);
                    blocksCflowDeobfuscator.Initialize(blocks);
                    blocksCflowDeobfuscator.Deobfuscate();
                    blocks.RepartitionBlocks();
                    IList<Instruction> list;
                    IList<ExceptionHandler> exceptionHandlers;
                    blocks.GetCode(out list, out exceptionHandlers);
                    DotNetUtils.RestoreBody(method, list, exceptionHandlers);
                }
            }
        }
        internal static string Base64(string BnlHf7xA)
        {
            byte[] bytes = Convert.FromBase64String(BnlHf7xA);
            return Encoding.UTF8.GetString(bytes);
        }
        public static Stream res = null;
        public static void GetRes2(ModuleDefMD module)
        {
            foreach(EmbeddedResource ress in module.Resources)
            {
                if(ress.Name.Contains(resourcename))
                {
                    res = ress.GetResourceStream();
                }
            }
        }
        public static Stream GetRes(ModuleDefMD module)
        {
            foreach(EmbeddedResource ress in module.Resources)
            {
                   return ress.GetResourceStream();
            }
            return null;
        }
        internal static string Decrypter(int nkApvZZz)
        {
            try
            {
                return Base64(new BinaryReader(res)
                {
                    BaseStream =
                {
           Position = (long)nkApvZZz
                }
                }.ReadString());
            }
            catch
            {
                return "";
            }
                
            
        }

        public static void DeobfuscatorBase(ModuleDefMD module)
        {
            foreach (TypeDef type in module.Types)
            {
                foreach (MethodDef method in type.Methods)
                {
                    if (method.HasBody == false)
                        continue;
                    for (int i = 0; i < method.Body.Instructions.Count; i++)
                    {
                        if (method.Body.Instructions[i].OpCode == OpCodes.Call && method.Body.Instructions[i].Operand.ToString().Contains(decryptionname) && method.Body.Instructions[i].Operand.ToString().Contains(proxymethodname))
                        {
                            try
                            {
                                if (method.Body.Instructions[i - 1].IsLdcI4())
                                {
                                    int num1 = Convert.ToInt32(method.Body.Instructions[i - 1].Operand);
                                    string decrypted = Decrypter(num1);
                                    method.Body.Instructions[i].OpCode = OpCodes.Ldstr;
                                    method.Body.Instructions[i].Operand = decrypted;
                                    method.Body.Instructions[i - 1].OpCode = OpCodes.Nop;
                                    DeobedString++;
                                }
                            }
                            catch
                            {

                            }
                            
                        }
                    }
                }
            }
        }
        private void button1_Click(object sender, EventArgs e)
        {
            Application.Exit();
        }
        private void pictureBox1_Click(object sender, EventArgs e)
        {

        }

        private void button2_Click(object sender, EventArgs e)
        {
        }
    }
}
