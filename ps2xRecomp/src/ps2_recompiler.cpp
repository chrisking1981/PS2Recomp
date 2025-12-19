#include "ps2recomp/ps2_recompiler.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <stdexcept>
#include <filesystem>
#include <set>

namespace fs = std::filesystem;

// Reserved C++ keywords and common conflicts that cannot be used as function names
static const std::set<std::string> RESERVED_NAMES = {
    // C++ keywords
    "std", "new", "delete", "class", "struct", "union", "enum", "namespace",
    "template", "typename", "typedef", "using", "virtual", "override", "final",
    "public", "private", "protected", "friend", "inline", "static", "extern",
    "const", "volatile", "mutable", "register", "auto", "explicit", "export",
    "throw", "try", "catch", "noexcept", "nullptr", "true", "false", "bool",
    "char", "short", "int", "long", "float", "double", "void", "signed", "unsigned",
    "if", "else", "switch", "case", "default", "while", "do", "for", "break",
    "continue", "return", "goto", "sizeof", "alignof", "decltype", "typeid",
    "const_cast", "static_cast", "dynamic_cast", "reinterpret_cast",
    "and", "or", "not", "xor", "bitand", "bitor", "compl", "and_eq", "or_eq",
    "xor_eq", "not_eq",
    // Common C library names that may conflict
    "main", "printf", "scanf", "malloc", "free", "exit", "abort",
    // Windows-specific
    "near", "far", "pascal"
};

namespace ps2recomp
{

    PS2Recompiler::PS2Recompiler(const std::string &configPath)
        : m_configManager(configPath)
    {
    }

    bool PS2Recompiler::initialize()
    {
        try
        {
            m_config = m_configManager.loadConfig();

            for (const auto &name : m_config.skipFunctions)
            {
                m_skipFunctions[name] = true;
            }

            m_elfParser = std::make_unique<ElfParser>(m_config.inputPath);
            if (!m_elfParser->parse())
            {
                std::cerr << "Failed to parse ELF file: " << m_config.inputPath << std::endl;
                return false;
            }

            m_functions = m_elfParser->extractFunctions();
            m_symbols = m_elfParser->extractSymbols();
            m_sections = m_elfParser->getSections();
            m_relocations = m_elfParser->getRelocations();

            std::cout << "Extracted " << m_functions.size() << " functions, "
                      << m_symbols.size() << " symbols, "
                      << m_sections.size() << " sections, "
                      << m_relocations.size() << " relocations." << std::endl;

            // Sanitize function names (fix duplicates and reserved C++ names)
            // Note: This builds m_renamedFunctions but doesn't pass to code generator yet
            sanitizeFunctionNames();

            m_decoder = std::make_unique<R5900Decoder>();
            m_codeGenerator = std::make_unique<CodeGenerator>(m_symbols);

            // Now pass renamed functions to code generator
            m_codeGenerator->setRenamedFunctions(m_renamedFunctions);

            fs::create_directories(m_config.outputPath);

            return true;
        }
        catch (const std::exception &e)
        {
            std::cerr << "Error during initialization: " << e.what() << std::endl;
            return false;
        }
    }

    bool PS2Recompiler::recompile()
    {
        try
        {
            std::cout << "Recompiling " << m_functions.size() << " functions..." << std::endl;

            std::string runtimeHeader = generateRuntimeHeader();
            fs::path runtimeHeaderPath = fs::path(m_config.outputPath) / "ps2_runtime_macros.h";

            writeToFile(runtimeHeaderPath.string(), runtimeHeader);

            size_t processedCount = 0;
            for (auto &function : m_functions)
            {
                std::cout << "processing function: " << function.name << std::endl;

                if (shouldSkipFunction(function.name))
                {
                    std::cout << "Skipping function: " << function.name << std::endl;
                    continue;
                }

                if (!decodeFunction(function))
                {
                    std::cerr << "Failed to decode function: " << function.name << std::endl;
                    return false;
                }

                function.isRecompiled = true;
#if _DEBUG
                processedCount++;
                if (processedCount % 100 == 0)
                {
                    std::cout << "Processed " << processedCount << " functions." << std::endl;
                }
#endif
            }

            std::cout << "Recompilation completed successfully." << std::endl;
            return true;
        }
        catch (const std::exception &e)
        {
            std::cerr << "Error during recompilation: " << e.what() << std::endl;
            return false;
        }
    }

    void PS2Recompiler::generateOutput()
    {
        try
        {
            generateFunctionHeader();

            if (m_config.singleFileOutput)
            {
                std::stringstream combinedOutput;

                combinedOutput << "#include \"ps2_recompiled_functions.h\"\n\n";
                combinedOutput << "#include \"ps2_runtime_macros.h\"\n";
                combinedOutput << "#include \"ps2_runtime.h\"\n";
                combinedOutput << "#include \"ps2_recompiled_stubs.h\"\n";

                for (const auto &function : m_functions)
                {
                    if (!function.isRecompiled)
                    {
                        continue;
                    }

                    try
                    {
                        if (function.isStub)
                        {
                            combinedOutput << m_generatedStubs.at(function.start) << "\n\n";
                        }
                        else
                        {
                            const auto &instructions = m_decodedFunctions.at(function.start);
                            std::string code = m_codeGenerator->generateFunction(function, instructions, false);
                            combinedOutput << code << "\n\n";
                        }
                    }
                    catch (const std::exception &e)
                    {
                        std::cerr << "Error generating code for function "
                                  << function.name << " (start 0x"
                                  << std::hex << function.start << "): "
                                  << e.what() << std::endl;
                        throw;
                    }
                }

                fs::path outputPath = fs::path(m_config.outputPath) / "ps2_recompiled_functions.cpp";
                writeToFile(outputPath.string(), combinedOutput.str());
                std::cout << "Wrote recompiled to combined output to: " << outputPath << std::endl;
            }
            else
            {
                for (const auto &function : m_functions)
                {
                    if (!function.isRecompiled || function.isStub)
                    {
                        continue;
                    }

                    std::string code;
                    try
                    {
                        if (function.isStub)
                        {
                            code = m_generatedStubs[function.start];
                        }
                        else
                        {
                            const auto &instructions = m_decodedFunctions[function.start];
                            code = m_codeGenerator->generateFunction(function, instructions, true);
                        }
                    }
                    catch (const std::exception &e)
                    {
                        std::cerr << "Error generating code for function "
                                  << function.name << " (start 0x"
                                  << std::hex << function.start << "): "
                                  << e.what() << std::endl;
                        throw;
                    }

                    fs::path outputPath = getOutputPath(function);
                    fs::create_directories(outputPath.parent_path());
                    writeToFile(outputPath.string(), code);
                }

                std::cout << "Wrote individual function files to: " << m_config.outputPath << std::endl;
            }

            std::string registerFunctions = m_codeGenerator->generateFunctionRegistration(
                m_functions, m_generatedStubs);

            fs::path registerPath = fs::path(m_config.outputPath) / "register_functions.cpp";
            writeToFile(registerPath.string(), registerFunctions);
            std::cout << "Generated function registration file: " << registerPath << std::endl;

            generateStubHeader();
        }
        catch (const std::exception &e)
        {
            std::cerr << "Error during output generation: " << e.what() << std::endl;
        }
    }

    bool PS2Recompiler::generateStubHeader()
    {
        try
        {
            std::stringstream ss;

            ss << "#pragma once\n\n";
            ss << "#include <cstdint>\n";
            ss << "#include \"ps2_runtime.h\"\n";
            ss << "#include \"ps2_syscalls.h\"\n\n";
            // ss << "namespace ps2recomp {\n";
            // ss << "namespace stubs {\n\n";

            for (const auto &funcName : m_config.skipFunctions)
            {
                ss << "void " << funcName << "(uint8_t* rdram, R5900Context* ctx, PS2Runtime* runtime) { ps2_syscalls::TODO(rdram, ctx, runtime); }\n";
            }

            // ss << "\n} // namespace stubs\n";
            // ss << "} // namespace ps2recomp\n";

            fs::path headerPath = fs::path(m_config.outputPath) / "ps2_recompiled_stubs.h";
            writeToFile(headerPath.string(), ss.str());

            std::cout << "Generated generating header file: " << headerPath << std::endl;
            return true;
        }
        catch (const std::exception &e)
        {
            std::cerr << "Error generating stub header: " << e.what() << std::endl;
            return false;
        }
    }

    bool PS2Recompiler::generateFunctionHeader()
    {
        try
        {
            std::stringstream ss;

            ss << "#ifndef PS2_RECOMPILED_FUNCTIONS_H\n";
            ss << "#define PS2_RECOMPILED_FUNCTIONS_H\n\n";

            ss << "#include <cstdint>\n\n";
            ss << "struct R5900Context;\n";
            ss << "class PS2Runtime;\n\n";

            for (const auto &function : m_functions)
            {
                if (function.isRecompiled)
                {
                    ss << "void " << function.name << "(uint8_t* rdram, R5900Context* ctx, PS2Runtime *runtime);\n";
                }
            }

            ss << "\n#endif // PS2_RECOMPILED_FUNCTIONS_H\n";

            fs::path headerPath = fs::path(m_config.outputPath) / "ps2_recompiled_functions.h";
            writeToFile(headerPath.string(), ss.str());

            std::cout << "Generated function header file: " << headerPath << std::endl;
            return true;
        }
        catch (const std::exception &e)
        {
            std::cerr << "Error generating function header: " << e.what() << std::endl;
            return false;
        }
    }

    bool PS2Recompiler::decodeFunction(Function &function)
    {
        std::vector<Instruction> instructions;

        uint32_t start = function.start;
        uint32_t end = function.end;

        for (uint32_t address = start; address < end; address += 4)
        {
            try
            {
                if (!m_elfParser->isValidAddress(address))
                {
                    std::cerr << "Invalid address: 0x" << std::hex << address << std::dec
                              << " in function: " << function.name << std::endl;
                    return false;
                }

                uint32_t rawInstruction = m_elfParser->readWord(address);

                auto patchIt = m_config.patches.find(address);
                if (patchIt != m_config.patches.end())
                {
                    rawInstruction = std::stoul(patchIt->second, nullptr, 0);
                    std::cout << "Applied patch at 0x" << std::hex << address << std::dec << std::endl;
                }

                Instruction inst = m_decoder->decodeInstruction(address, rawInstruction);

                instructions.push_back(inst);
            }
            catch (const std::exception &e)
            {
                std::cerr << "Error decoding instruction at 0x" << std::hex << address << std::dec
                          << " in function: " << function.name << ": " << e.what() << std::endl;
                return false;
            }
        }

        m_decodedFunctions[function.start] = instructions;

        return true;
    }

    bool PS2Recompiler::shouldSkipFunction(const std::string &name) const
    {
        return m_skipFunctions.find(name) != m_skipFunctions.end();
    }

    void PS2Recompiler::sanitizeFunctionNames()
    {
        // Track how many times each name has been used
        std::unordered_map<std::string, int> nameCount;

        // First pass: count occurrences and rename reserved names
        for (auto &function : m_functions)
        {
            std::string originalName = function.name;

            // Check for reserved C++ names
            if (RESERVED_NAMES.find(function.name) != RESERVED_NAMES.end())
            {
                function.name = function.name + "_func";
                m_renamedFunctions[function.start] = function.name;
                std::cout << "Renamed reserved name: " << originalName
                          << " -> " << function.name
                          << " (at 0x" << std::hex << function.start << std::dec << ")" << std::endl;
            }

            // Track name usage
            nameCount[function.name]++;
        }

        // Second pass: rename duplicates
        std::unordered_map<std::string, int> currentIndex;
        for (auto &function : m_functions)
        {
            if (nameCount[function.name] > 1)
            {
                // This name is duplicated
                int index = ++currentIndex[function.name];
                if (index > 1)
                {
                    // Not the first occurrence, add suffix
                    std::string originalName = function.name;
                    function.name = function.name + "_" + std::to_string(index);
                    m_renamedFunctions[function.start] = function.name;
                    std::cout << "Renamed duplicate: " << originalName
                              << " -> " << function.name
                              << " (at 0x" << std::hex << function.start << std::dec << ")" << std::endl;
                }
            }
        }
    }

    std::string PS2Recompiler::generateRuntimeHeader()
    {
        return m_codeGenerator->generateMacroHeader();
    }

    bool PS2Recompiler::writeToFile(const std::string &path, const std::string &content)
    {
        std::ofstream file(path);
        if (!file)
        {
            std::cerr << "Failed to open file for writing: " << path << std::endl;
            return false;
        }

        file << content;
        file.close();

        return true;
    }

    std::filesystem::path PS2Recompiler::getOutputPath(const Function &function) const
    {
        std::string safeName = function.name;

        std::replace_if(safeName.begin(), safeName.end(), [](char c)
                        { return c == '/' || c == '\\' || c == ':' || c == '*' ||
                                 c == '?' || c == '"' || c == '<' || c == '>' ||
                                 c == '|' || c == '$'; }, '_');

        if (safeName.empty())
        {
            std::stringstream ss;
            ss << "func_" << std::hex << function.start;
            safeName = ss.str();
        }

        std::filesystem::path outputPath = m_config.outputPath;
        outputPath /= safeName + ".cpp";

        return outputPath;
    }
}
