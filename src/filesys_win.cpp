#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#endif /* _MSC_VER */

#include <cstddef>
#include <cstring>

#include <windows.h>
#include <shlwapi.h> // PathAppend etc

/* headers for the posix-style msvc CRT functions (ex _open, _fstat, _close) */
#include <io.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <gittest/misc.h>
#include <gittest/filesys.h>
#include <gittest/filesys_win.h>

static void gs_close_handle(HANDLE handle);

int gs_win_path_directory(
	const char *InputPathBuf, size_t LenInputPath,
	char *ioOutputPathBuf, size_t OutputPathBufSize, size_t *oLenOutputPath);
int gs_win_path_canonicalize(
	const char *InputPathBuf, size_t LenInputPath,
	char *ioOutputPathBuf, size_t OutputPathBufSize, size_t *oLenOutputPath);

void gs_close_handle(HANDLE handle)
{
	if (handle)
		if (!CloseHandle(handle))
			GS_ASSERT(0);
}

int gs_win_path_directory(
	const char *InputPathBuf, size_t LenInputPath,
	char *ioOutputPathBuf, size_t OutputPathBufSize, size_t *oLenOutputPath)
{
	int r = 0;

	char Drive[_MAX_DRIVE] = {};
	char Dir[_MAX_DIR] = {};
	char FName[_MAX_FNAME] = {};
	char Ext[_MAX_EXT] = {};

	/* http://www.flounder.com/msdn_documentation_errors_and_omissions.htm
	*    see for _splitpath: """no more than this many characters will be written to each buffer""" */
	_splitpath(InputPathBuf, Drive, Dir, FName, Ext);

	if (!!(r = _makepath_s(ioOutputPathBuf, OutputPathBufSize, Drive, Dir, NULL, NULL)))
		GS_GOTO_CLEAN();

	if (!!(r = gs_buf_strnlen(ioOutputPathBuf, OutputPathBufSize, oLenOutputPath)))
		GS_GOTO_CLEAN();

clean:

	return r;
}

int gs_win_path_canonicalize(
	const char *InputPathBuf, size_t LenInputPath,
	char *ioOutputPathBuf, size_t OutputPathBufSize, size_t *oLenOutputPath)
{
	int r = 0;

	/** required length for PathCanonicalize **/
	if (OutputPathBufSize < MAX_PATH || LenInputPath > MAX_PATH)
		GS_ERR_CLEAN(1);

	/** this does fucking nothing (ex retains mixed slash backslash) **/
	if (! PathCanonicalize(ioOutputPathBuf, InputPathBuf))
		GS_ERR_CLEAN(1);

	if (!!(r = gs_buf_strnlen(ioOutputPathBuf, OutputPathBufSize, oLenOutputPath)))
		GS_GOTO_CLEAN();

clean:

	return r;
}

int gs_build_path_expand_separated(
	const char *PathBuf, size_t LenPath,
	const char *ExtBuf, size_t LenExt,
	const char *SeparatorBuf, size_t LenSeparator,
	char *ExpandedBuf, size_t ExpandedSize, size_t *oLenExpanded)
{
	int r = 0;

	char PatternBuf[1024] = {};
	size_t LenPattern = 0;

	HANDLE hFind = INVALID_HANDLE_VALUE;
	WIN32_FIND_DATA FindData = {};
	DWORD dwError = ERROR_FILE_NOT_FOUND;

	std::string Accum;

	if (!!(r = gs_path_append_abs_rel(
		PathBuf, LenPath,
		ExtBuf, LenExt,
		PatternBuf, sizeof PatternBuf, &LenPattern)))
	{
		GS_GOTO_CLEAN();
	}

	if (!!(r = gs_buf_ensure_haszero(PatternBuf, LenPattern + 1)))
		GS_GOTO_CLEAN();

	if ((INVALID_HANDLE_VALUE == (hFind = FindFirstFile(PatternBuf, &FindData))) &&
		(ERROR_FILE_NOT_FOUND != (dwError = GetLastError())))
	{
		GS_ERR_CLEAN(1);
	}

	if (INVALID_HANDLE_VALUE != hFind) {
		DWORD dwError2 = 0;

		do {
			size_t LenFileName = 0;

			char TmpBuf[1024] = {};
			size_t LenTmp = 0;

			if (!!(r = gs_buf_strnlen(FindData.cFileName, MAX_PATH, &LenFileName)))
				GS_GOTO_CLEAN();

			if (!!(r = gs_path_append_abs_rel(
				PathBuf, LenPath,
				FindData.cFileName, LenFileName,
				TmpBuf, sizeof TmpBuf, &LenTmp)))
			{
				GS_GOTO_CLEAN();
			}

			Accum.append(TmpBuf, LenTmp);
			Accum.append(SeparatorBuf, LenSeparator);
		} while (FindNextFile(hFind, &FindData) != 0);

		if (ERROR_NO_MORE_FILES != (dwError2 = GetLastError()))
			GS_ERR_CLEAN(1);
	}
	else {
		assert(ERROR_FILE_NOT_FOUND == dwError);
		Accum.append("");
	}

	if (Accum.size() + 1 >= ExpandedSize)
		GS_ERR_CLEAN(1);

	memmove(ExpandedBuf, Accum.data(), Accum.size());
	memset(ExpandedBuf + Accum.size(), '\0', 1);

	if (oLenExpanded)
		*oLenExpanded = Accum.size();

clean:
	if (hFind == INVALID_HANDLE_VALUE)
		FindClose(hFind);

	return r;
}

int gs_build_current_executable_relative_filename(
	const char *RelativeBuf, size_t LenRelative,
	char *ioCombinedBuf, size_t CombinedBufSize, size_t *oLenCombined)
{
	int r = 0;

	size_t LenPathCurrentExecutableDir = 0;
	char PathCurrentExecutableDirBuf[512] = {};
	size_t LenPathModification = 0;
	char PathModificationBuf[512] = {};

	/* get directory */
	if (!!(r = gs_get_current_executable_directory(
		PathCurrentExecutableDirBuf, sizeof PathCurrentExecutableDirBuf, &LenPathCurrentExecutableDir)))
	{
		GS_ERR_CLEAN(1);
	}

	/* ensure relative and append */

	if (!!(r = gs_path_append_abs_rel(
		PathCurrentExecutableDirBuf, LenPathCurrentExecutableDir,
		RelativeBuf, LenRelative,
		PathModificationBuf, sizeof PathModificationBuf, &LenPathModification)))
	{
		GS_GOTO_CLEAN();
	}

	/* canonicalize into output */

	if (!!(r = gs_win_path_canonicalize(
		PathModificationBuf, LenPathModification,
		ioCombinedBuf, CombinedBufSize, oLenCombined)))
	{
		GS_GOTO_CLEAN();
	}

clean:

	return r;
}

int gs_get_current_executable_filename(char *ioFileNameBuf, size_t FileNameSize, size_t *oLenFileName)
{
	int r = 0;

	DWORD LenFileName = 0;

	LenFileName = GetModuleFileName(NULL, ioFileNameBuf, FileNameSize);
	if (!(LenFileName != 0 && LenFileName < FileNameSize))
		GS_ERR_CLEAN(1);

	if (oLenFileName)
		*oLenFileName = LenFileName;

clean:

	return r;
}

int gs_get_current_executable_directory(
	char *ioCurrentExecutableDirBuf, size_t CurrentExecutableDirSize, size_t *oLenCurrentExecutableDir)
{
	int r = 0;

	size_t LenCurrentExecutable = 0;
	char CurrentExecutableBuf[512] = {};

	if (!!(r = gs_get_current_executable_filename(
		CurrentExecutableBuf, sizeof CurrentExecutableBuf, &LenCurrentExecutable)))
	{
		GS_GOTO_CLEAN();
	}

	if (!!(r = gs_win_path_directory(
		CurrentExecutableBuf, LenCurrentExecutable,
		ioCurrentExecutableDirBuf, CurrentExecutableDirSize, oLenCurrentExecutableDir)))
	{
		GS_GOTO_CLEAN();
	}

clean:

	return r;
}

int gs_file_exist(
	const char *FileNameBuf, size_t LenFileName,
	size_t *oIsExist)
{
	int r = 0;

	int IsExist = 0;

	if (!!(r = gs_buf_ensure_haszero(FileNameBuf, LenFileName + 1)))
		GS_GOTO_CLEAN();

	/* https://blogs.msdn.microsoft.com/oldnewthing/20071023-00/?p=24713/ */
	/* INVALID_FILE_ATTRIBUTES if file does not exist, apparently */
	IsExist = !(INVALID_FILE_ATTRIBUTES == GetFileAttributes(FileNameBuf));

	if (oIsExist)
		*oIsExist = IsExist;

clean:

	return r;
}

int gs_file_exist_ensure(const char *FileNameBuf, size_t LenFileName)
{
	int r = 0;

	if (!!(r = gs_buf_ensure_haszero(FileNameBuf, LenFileName + 1)))
		GS_GOTO_CLEAN();

	/* https://blogs.msdn.microsoft.com/oldnewthing/20071023-00/?p=24713/ */
	/* INVALID_FILE_ATTRIBUTES if file does not exist, apparently */
	if (INVALID_FILE_ATTRIBUTES == GetFileAttributes(FileNameBuf))
		GS_ERR_CLEAN(1);

clean:

	return r;
}

int gs_file_is_directory(const char *FileNameBuf, size_t LenFileName,
	size_t *oIsDirectory)
{
	int r = 0;

	DWORD Attributes = 0;

	if (!!(r = gs_buf_ensure_haszero(FileNameBuf, LenFileName + 1)))
		GS_GOTO_CLEAN();

	if (INVALID_FILE_ATTRIBUTES == (Attributes = GetFileAttributes(FileNameBuf)))
		GS_ERR_CLEAN(1);

	if (oIsDirectory)
		*oIsDirectory = !!(Attributes & FILE_ATTRIBUTE_DIRECTORY);

clean:

	return r;
}

int gs_path_is_absolute(const char *PathBuf, size_t LenPath, size_t *oIsAbsolute)
{
	int r = 0;

	size_t IsAbsolute = false;

	if (!!(r = gs_buf_strnlen(PathBuf, LenPath + 1, NULL)))
		GS_GOTO_CLEAN();

	/* maximum length for PathIsRelative */
	if (LenPath > MAX_PATH)
		GS_ERR_CLEAN(1);

	IsAbsolute = ! PathIsRelative(PathBuf);

	if (oIsAbsolute)
		*oIsAbsolute = IsAbsolute;

clean:

	return r;
}

int gs_path_append_abs_rel(
	const char *AbsoluteBuf, size_t LenAbsolute,
	const char *RelativeBuf, size_t LenRelative,
	char *ioOutputPathBuf, size_t OutputPathBufSize, size_t *oLenOutputPath)
{
	int r = 0;

	size_t LenOutputPathTmp = 0;

	/** maximum length for PathIsRelative and PathAppend **/
	if (LenAbsolute > MAX_PATH || LenRelative > MAX_PATH)
		GS_ERR_CLEAN(1);

	if (PathIsRelative(AbsoluteBuf))
		GS_GOTO_CLEAN();

	if (! PathIsRelative(RelativeBuf))
		GS_GOTO_CLEAN();

	/* prep output buffer with absolute path */

	if (!!(r = gs_buf_copy_zero_terminate(
		AbsoluteBuf, LenAbsolute,
		ioOutputPathBuf, OutputPathBufSize, &LenOutputPathTmp)))
	{
		GS_GOTO_CLEAN();
	}

	/* append */

	if (! PathAppend(ioOutputPathBuf, RelativeBuf))
		GS_ERR_CLEAN(1);

	if (!!(r = gs_buf_strnlen(ioOutputPathBuf, OutputPathBufSize, oLenOutputPath)))
		GS_GOTO_CLEAN();

clean:

	return r;
}

int gs_file_read_tobuffer_block(
	const char *FileNameBuf, size_t LenFileName,
	char *ioDataBuf, size_t DataSize, size_t *oLenData)
{
	int r = 0;

	int Fd = -1;
	int cnt = -1;
	size_t Offset = 0;

	if (!!(r = gs_buf_ensure_haszero(FileNameBuf, LenFileName + 1)))
		GS_GOTO_CLEAN();

	Fd = _open(FileNameBuf, _O_RDONLY | _O_BINARY);
	if (Fd == -1 && errno == ENOENT)
		GS_ERR_NO_CLEAN(GS_ERRCODE_NOTFOUND);
	if (Fd == -1)
		GS_GOTO_CLEAN();

	while ((cnt = _read(Fd, ioDataBuf + Offset, DataSize - Offset)) > 0 && Offset <= DataSize)
		Offset += cnt;

	if (cnt != 0)
		GS_ERR_CLEAN(1);

noclean:
	if (oLenData)
		*oLenData = Offset;

clean:
	if (Fd != -1)
		_close(Fd);

	return r;
}

int gs_file_write_frombuffer(
	const char *FileNameBuf, size_t LenFileName,
	uint8_t *BufferUpdateData, uint32_t BufferUpdateSize)
{
	int r = 0;

	HANDLE hTempFile = INVALID_HANDLE_VALUE;

	DWORD NumberOfBytesWritten = 0;

	BOOL Ok = 0;

	if (!!(r = gs_buf_ensure_haszero(FileNameBuf, LenFileName + 1)))
		GS_GOTO_CLEAN();

	if ((hTempFile = CreateFile(
		FileNameBuf,
		GENERIC_WRITE,
		FILE_SHARE_DELETE,
		NULL,
		CREATE_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		NULL)) == INVALID_HANDLE_VALUE)
	{
		GS_ERR_CLEAN(1);
	}

	if (!(Ok = WriteFile(hTempFile, BufferUpdateData, BufferUpdateSize, &NumberOfBytesWritten, NULL)))
		GS_ERR_CLEAN(1);

	if (NumberOfBytesWritten != BufferUpdateSize)
		GS_ERR_CLEAN(1);

clean:
	if (hTempFile != INVALID_HANDLE_VALUE)
		CloseHandle(hTempFile);
	
	return r;
}

int gs_rename_wrapper(
	const char *SrcFileNameBuf, size_t LenSrcFileName,
	const char *DstFileNameBuf, size_t LenDstFileName)
{
	int r = 0;

	BOOL Ok = 0;

	if (!!(r = gs_buf_ensure_haszero(SrcFileNameBuf, LenSrcFileName + 1)))
		GS_GOTO_CLEAN();

	if (!!(r = gs_buf_ensure_haszero(DstFileNameBuf, LenDstFileName + 1)))
		GS_GOTO_CLEAN();

	if (!(Ok = MoveFileEx(SrcFileNameBuf, DstFileNameBuf, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)))
		GS_ERR_CLEAN(1);

clean:

	return r;
}

int gs_directory_create_unless_exist(
	const char *DirNameBuf, size_t LenDirName)
{
	int r = 0;

	if (!!(r = gs_buf_ensure_haszero(DirNameBuf, LenDirName + 1)))
		GS_GOTO_CLEAN();

	if (!CreateDirectory(DirNameBuf, NULL)) {
		DWORD Error = GetLastError();
		if (Error == ERROR_ALREADY_EXISTS)
			GS_ERR_NO_CLEAN(0);
		GS_ERR_CLEAN(1);
	}

noclean:

clean:

	return r;
}

int gs_process_start_ex(
	const char *FileNameParentBuf, size_t LenFileNameParent,
	const char *CmdLineBuf, size_t LenCmdLine)
{
	/* create a process and discard all the handles (process and thread handles) */
	int r = 0;

	std::string Argv;

	STARTUPINFO si = {};
	PROCESS_INFORMATION pi = {};
	HANDLE hChildProcess = NULL;
	HANDLE hChildThread = NULL;

	/* https://msdn.microsoft.com/en-us/library/windows/desktop/ms682425(v=vs.85).aspx
	*    32768 actually */
	const size_t MagicCommandLineLenghtLimit = 32767;
	const size_t ReasonableCommandLineLengthLimit = 1024;
	char CmdLineCopyBuf[ReasonableCommandLineLengthLimit];
	size_t LenCmdLineCopy = 0;

	BOOL Ok = 0;
	DWORD ExitCode = 0;

	if (!!(r = gs_buf_ensure_haszero(FileNameParentBuf, LenFileNameParent + 1)))
		GS_GOTO_CLEAN();

	if (!!(r = gs_buf_ensure_haszero(CmdLineBuf, LenCmdLine + 1)))
		GS_GOTO_CLEAN();

	Argv.append("\"", 1);
	Argv.append(FileNameParentBuf);
	Argv.append("\"", 1);

	for (size_t Offset = 0; Offset < LenCmdLine; Offset ++) {
		Argv.append(" ", 1);
		Argv.append("\"", 1);
		Argv.append(&CmdLineBuf[Offset]);
		Argv.append("\"", 1);
		while (Offset < LenCmdLine && CmdLineBuf[Offset] != '\0')
			Offset++;
	}

	if (!!(r = gs_buf_copy_zero_terminate(
		Argv.data(), Argv.size(),
		CmdLineCopyBuf, sizeof CmdLineCopyBuf, &LenCmdLineCopy)))
	{
		GS_GOTO_CLEAN();
	}

	if (!!(r = gs_file_exist_ensure(FileNameParentBuf, LenFileNameParent)))
		GS_GOTO_CLEAN();

	ZeroMemory(&si, sizeof si);
	si.cb = sizeof si;
	ZeroMemory(&pi, sizeof pi);

	if (!(Ok = CreateProcess(
		FileNameParentBuf,
		CmdLineCopyBuf,
		NULL,
		NULL,
		TRUE,
		0, /* CREATE_NEW_CONSOLE - meh it closes on quit */
		NULL,
		NULL,
		&si,
		&pi)))
	{
		GS_ERR_CLEAN(1);
	}
	hChildProcess = pi.hProcess;
	hChildThread = pi.hThread;

	if (WAIT_OBJECT_0 != WaitForSingleObject(hChildProcess, GS_FILESYS_ARBITRARY_TIMEOUT_MSEC))
		GS_ERR_CLEAN(1);

	if (! GetExitCodeProcess(hChildProcess, &ExitCode))
		GS_ERR_CLEAN(1);

	// FIXME: is there an official success exit code? constant zero or something?
	if (ExitCode != EXIT_SUCCESS)
		GS_ERR_CLEAN(1);

clean:
	gs_close_handle(hChildThread);

	gs_close_handle(hChildProcess);

	return r;
}

int gs_posixstyle_open_read(const char *Filename)
{
	return _open(Filename, _O_RDONLY | _O_BINARY);
}

int gs_posixstyle_fstat(int Fd, struct gs_stat *ioStat)
{
	int r = 0;

	struct _stat Stat = {};

	if (!!(r = _fstat(Fd, &Stat)))
		GS_GOTO_CLEAN();

	ioStat->mStMode_IfReg = (Stat.st_mode & _S_IFMT) == _S_IFREG;
	ioStat->mStSize = Stat.st_size;

clean:

	return r;
}

int gs_posixstyle_close(int Fd)
{
	return _close(Fd);
}

void gs_close_cond(int Fd)
{
	if (Fd != -1)
		_close(Fd);
}
