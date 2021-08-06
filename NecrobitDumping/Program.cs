using System;
using System.Collections;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using AsmResolver.DotNet;
using AsmResolver.DotNet.Code.Cil;
using AsmResolver.IO;
using AsmResolver.PE;
using AsmResolver.PE.DotNet.Cil;
using AsmResolver.PE.DotNet.Metadata.Tables;
using AsmResolver.PE.DotNet.Metadata.Tables.Rows;

namespace NecrobitDumping
{
    internal class Program
    {
        public static void Main(string[] args)
        {
            var assembly = Assembly.LoadFrom("NecrobitTest.exe");

            var type = assembly.GetTypes().First(d => d.Name == "nLvrU8AQJDKRRZAB7e");
            var hashtableField = type.GetRuntimeFields().First(d => d.Name == "Nll0SVdCxp");

            var hashtableValue = (Hashtable) hashtableField.GetValue(null);
            var hInstance = Marshal.GetHINSTANCE(assembly.ManifestModule).ToInt64();

            var peImage = PEImage.FromFile("NecrobitTest.exe");
            var module = ModuleDefinition.FromFile("NecrobitTest.exe");
            var table = peImage.DotNetDirectory.Metadata.GetStream<TablesStream>().GetTable<MethodDefinitionRow>()
                .ToList();
            foreach (DictionaryEntry entry in hashtableValue)
            {
                var cilBytes = ExtractArray(entry.Value);
                var rva = (long) entry.Key - hInstance - 1;
                var row = table.SingleOrDefault(d => d.Body.Rva == rva);
                var index = table.IndexOf(row) + 1;
                var token = new MetadataToken(row.TableIndex, (uint) index);
                if (module.TryLookupMember(token, out var m))
                {
                    if (m is MethodDefinition methodDefinition)
                    {
                        Console.WriteLine(methodDefinition.Name);
                        var operandResolver =
                            new PhysicalCilOperandResolver(module,
                                methodDefinition.CilMethodBody);
                        BinaryStreamReader reader = ByteArrayDataSource.CreateReader(cilBytes);
                        var disassembler = new CilDisassembler(in reader, operandResolver);
                        var instructions = disassembler.ReadInstructions();
                        methodDefinition.CilMethodBody.Instructions.Clear();
                        methodDefinition.CilMethodBody.Instructions.AddRange(instructions);
                    }
                }
            }
            
            module.Write("NecrobitTest-UnNecrobit.exe");

            byte[] ExtractArray(object entry)
            {
                foreach (var field in entry.GetType().GetRuntimeFields())
                {
                    if (field.FieldType == typeof(byte[]))
                    {
                        return (byte[]) field.GetValue(entry);
                    }
                }

                return new byte[0];
            }
        }
    }
}