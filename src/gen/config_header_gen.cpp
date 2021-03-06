#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#endif /* _MSC_VER */

#include <cstdlib>
#include <cstddef>

#include <fstream>
#include <sstream>
#include <string>

#define OPT_IDENTIFIER "--identifier"

#define HEADER_VAR_IDENTIFIER "GS_CONFIG_BUILTIN_HEXSTRING"
#define DOUBLEQUOTE "\""

void header_gen(
	std::string HeaderVarIdentifier,
	std::string SrcHex,
	std::string *oRet);
void hex_encode_buf(
	std::string Buf,
	std::string *oRet);
int main(int argc, char **argv);

void header_gen(
	std::string HeaderVarIdentifier,
	std::string SrcHex,
	std::string *oRet)
{
	std::stringstream ss;
	std::string str;

	ss << "/* generated by config_header_gen.cpp - do not edit */" << std::endl;
	//ss << "#define " << HeaderVarIdentifier << " "
	//	<< DOUBLEQUOTE << SrcHex << DOUBLEQUOTE
	//	<< std::endl;
	ss << "char " << HeaderVarIdentifier << "[] = {";
	for (size_t i = 0; i < SrcHex.size(); i++)
		ss << '\'' << SrcHex[i] << '\'' << ',';
	ss << "};" << std::endl;

	str = ss.str();
	oRet->swap(str);
}

void hex_encode_buf(
	std::string Buf,
	std::string *oRet)
{
	for (size_t i = 0; i < Buf.size(); i++) {
		const char Chars[] = "0123456789ABCDEF";
		oRet->append(1, Chars[Buf[i] & 0x0F]);
		oRet->append(1, Chars[(Buf[i] >> 4) & 0x0F]);
	}
}

int main(int argc, char **argv)
{
	int r = 0;

	if (argc < 5)
		return EXIT_FAILURE;

	const std::string IdentifierOpt(argv[1]);
	const std::string IdentifierArg(argv[2]);
	const std::string SrcArg(argv[3]);
	const std::string DstArg(argv[4]);

	/* sanity check */
	if (IdentifierOpt                    != std::string(OPT_IDENTIFIER) ||
		DstArg.substr(DstArg.size() - 2) != std::string(".h"))
	{
		return EXIT_FAILURE;
	}

	try {
		std::stringstream SrcStream;
		std::string SrcHex, SrcHdr;

		/* read raw config file */
		std::ifstream SrcFile(SrcArg, std::ios::in | std::ios::binary);
		SrcStream << SrcFile.rdbuf();
		if (SrcFile.bad())
			return EXIT_FAILURE;

		/* transform raw config file into header */
		hex_encode_buf(SrcStream.str(), &SrcHex);
		header_gen(IdentifierArg, SrcHex, &SrcHdr);

		/* write header file */
		std::ofstream DstFile(DstArg, std::ios::out | std::ios::binary);
		DstFile << SrcHdr;
		if (DstFile.bad())
			return EXIT_FAILURE;
	} catch (std::exception &) {
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
