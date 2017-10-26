#include <cstddef>
#include <cstdlib>
#include <cstring>

#include <vector>

#include <signal.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>
#include <glob.h>

#include <gittest/misc.h>
#include <gittest/filesys.h>
#include <gittest/filesys_nix.h>

/* http://pubs.opengroup.org/onlinepubs/7908799/xsh/systypes.h.html 
*    pid_t is an intergral type */

int gs_nix_open_wrapper(
	const char *LogFileNameBuf, size_t LenLogFileName,
	int OpenFlags, mode_t OpenMode,
	int *oFdLogFile);
int gs_nix_close_wrapper(int fd);
int gs_nix_close_wrapper_noerr(int fd);
int gs_nix_access_wrapper(
	const char *InputPathBuf, size_t LenInpuPath,
	int mode);
int gs_nix_readlink_wrapper(
	const char *InputPathBuf, size_t LenInputPath,
	char *ioFileNameBuf, size_t FileNameSize, size_t *oLenFileName);

int gs_nix_path_eat_trailing_slashes(
	const char *InputPathBuf, size_t LenInputPath,
	size_t *oNewLen);
int gs_nix_path_eat_trailing_nonslashes(
	const char *InputPathBuf, size_t LenInputPath,
	size_t *oNewLen);
int gs_nix_path_ensure_starts_with_lump(
	const char *InputPathBuf, size_t LenInputPath);
int gs_nix_path_add_trailing_slash_cond_inplace(
	char *DataStart, size_t DataLength, size_t OffsetOnePastEnd, size_t *OffsetOnePastEndNew);
int gs_nix_path_append_midslashing_inplace(
	const char *ToAddBuf, size_t LenToAdd,
	char *DataStart, size_t DataLength, size_t OffsetOnePastEnd, size_t *OffsetOnePastEndNew);

int gs_nix_path_ensure_absolute(const char *PathBuf, size_t LenPath);
int gs_nix_absolute_path_directory(
	const char *InputPathBuf, size_t LenInputPath,
	char *ioOutputPathBuf, size_t OutputPathBufSize, size_t *oLenOutputPath);

int gs_nix_open_wrapper(
	const char *FileNameBuf, size_t LenFileName,
	int OpenFlags, mode_t OpenMode,
	int *oFdFile)
{
	/* http://man7.org/linux/man-pages/man7/signal-safety.7.html
	*    async-signal-safe functions: open is listed */

	/* http://man7.org/linux/man-pages/man2/open.2.html
	*    O_CREAT and O_TMPFILE flags mandate use of the third (mode) argument to open */

	int r = 0;

	int fdFile = -1;

	while (-1 == (fdFile = open(FileNameBuf, OpenFlags, OpenMode))) {
		if (errno == EINTR)
			continue;
		else
			{ r = 1; goto clean; }
	}

	if (oFdFile)
		*oFdFile = fdFile;

clean:
	if (!!r) {
		gs_nix_close_wrapper_noerr(fdFile);
	}

	return r;
}

int gs_nix_close_wrapper(int fd) {
	/* http://man7.org/linux/man-pages/man7/signal-safety.7.html
	*    async-signal-safe functions: close is listed */

	int r = 0;

	if (fd == -1)
		{ r = 0; goto noclean; }

	while (!!close(fd)) {
		if (errno == EINTR)
			continue;
		else
			{ r = 1; goto clean; }
	}

noclean:

clean:

	return r;
}

int gs_nix_close_wrapper_noerr(int fd) {
	if (!!gs_nix_close_wrapper(fd))
		{ /* dummy */ }
}

int gs_nix_access_wrapper(
	const char *InputPathBuf, size_t LenInpuPath,
	int mode)
{
	/* http://man7.org/linux/man-pages/man7/signal-safety.7.html
	*    async-signal-safe functions: access is listed */

	int r = 0;

	if (!!access(InputPathBuf, mode))
		{ r = 1; goto clean; }

clean:

	return r;
}

int gs_nix_readlink_wrapper(
	const char *InputPathBuf, size_t LenInputPath,
	char *ioFileNameBuf, size_t FileNameSize, size_t *oLenFileName)
{
	/* http://man7.org/linux/man-pages/man7/signal-safety.7.html
	*    async-signal-safe functions: readlink is listed
	*  realpath is readlink's competitor for this task but not listed */

	int r = 0;

	size_t LenFileName = 0;
	ssize_t count = 0;

	if (-1 == (count = readlink(InputPathBuf, ioFileNameBuf, FileNameSize)))
		{ r = 1; goto clean; }

	if (count >= FileNameSize)
		{ r = 1; goto clean; }

	/* count >= 0 && count < FileNameSize */

	/* readlink does not zero terminate */
	ioFileNameBuf[count] = '\0';
	LenFileName = count;

	if (oLenFileName)
		*oLenFileName = LenFileName;

clean:

	return r;
}

int gs_nix_path_eat_trailing_slashes(
	const char *InputPathBuf, size_t LenInputPath,
	size_t *oNewLen)
{
	int r = 0;

	if (LenInputPath < 1)
		{ r = 1; goto clean; }

	while ((LenInputPath - 1) && InputPathBuf[(LenInputPath - 1)] == '/')
		LenInputPath--;

	if (oNewLen)
		*oNewLen = LenInputPath;

clean:

	return r;
}

int gs_nix_path_eat_trailing_nonslashes(
	const char *InputPathBuf, size_t LenInputPath,
	size_t *oNewLen)
{
	int r = 0;

	if (LenInputPath < 1)
	{ r = 1; goto clean; }

	while ((LenInputPath - 1) && InputPathBuf[(LenInputPath - 1)] != '/')
		LenInputPath--;

	if (oNewLen)
		*oNewLen = LenInputPath;

clean:

	return r;
}

int gs_nix_path_ensure_starts_with_lump(
	const char *InputPathBuf, size_t LenInputPath)
{
	int r = 0;

	size_t CurPos = 0;
	size_t CurPosMarker = 0;

	while (CurPos < LenInputPath && InputPathBuf[CurPos] == '/')
		CurPos++;

	/* no advance? */
	if ((CurPos - CurPosMarker) == 0)
		{ r = 1; goto clean; }

	CurPos = CurPos;
	CurPosMarker = CurPos;

	while (CurPos < LenInputPath && InputPathBuf[CurPos] != '/')
		CurPos++;

	/* no advance? */
	if ((CurPos - CurPosMarker) == 0)
		{ r = 1; goto clean; }

clean:

	return r;
}

int gs_nix_path_add_trailing_slash_cond_inplace(
	char *DataStart, size_t DataLength, size_t OffsetOnePastEnd, size_t *OffsetOnePastEndNew)
{
	int r = 0;

	size_t Offset = OffsetOnePastEnd - 1;

	/* already ending with slash */
	if (DataStart[Offset++] == '/')
		{ r = 0; goto clean; }

	if (DataLength - Offset < 1 + 1)
		{ r = 1; goto clean; }

	DataStart[Offset++] = '/';  /* 1 */
	DataStart[Offset++] = '\0'; /* 1 */

	Offset--; /* we want to end at the inserted zero */

	if (OffsetOnePastEndNew)
		*OffsetOnePastEndNew = Offset;

clean:

	return r;
}

int gs_nix_path_append_midslashing_inplace(
	const char *ToAddBuf, size_t LenToAdd,
	char *DataStart, size_t DataLength, size_t OffsetOnePastEnd, size_t *OffsetOnePastEndNew)
{
	int r = 0;

	size_t Offset = OffsetOnePastEnd;

	if (!!(r = gs_nix_path_add_trailing_slash_cond_inplace(DataStart, DataLength, Offset, &Offset)))
		goto clean;

	if (DataLength - Offset < LenToAdd + 1)
		{ r = 1; goto clean; }

	memmove(DataStart + Offset, ToAddBuf, LenToAdd); /* LenToAdd */
	Offset += LenToAdd;
	DataStart[Offset++] = '\0'; /* 1 */

	Offset--; /* want to end up at the inserted zero */

	if (OffsetOnePastEndNew)
		*OffsetOnePastEndNew = Offset;

clean:

	return r;
}

int gs_nix_path_ensure_absolute(const char *PathBuf, size_t LenPath)
{
	int r = 0;

	size_t IsAbsolute = 0;

	if (!!(r = gs_path_is_absolute(PathBuf, LenPath, &IsAbsolute)))
		goto clean;

	if (! IsAbsolute)
		{ r = 1; goto clean; }

clean:

	return r;
}

int gs_nix_absolute_path_directory(
	const char *InputPathBuf, size_t LenInputPath,
	char *ioOutputPathBuf, size_t OutputPathBufSize, size_t *oLenOutputPath)
{
	/* async-signal-safe functions: safe */
	int r = 0;

	size_t LenOutputPath = 0;

	const char OnlySlash[] = "/";

	const char *ToOutputPtr = NULL;
	size_t ToOutputLen = 0;

	/* absolute aka starts with a slash */
	if (!!(r = gs_nix_path_ensure_absolute(InputPathBuf, LenInputPath)))
		goto clean;

	/* eat trailing slashes */

	if (!!(r = gs_nix_path_eat_trailing_slashes(InputPathBuf, LenInputPath, &LenInputPath)))
		goto clean;

	if (LenInputPath > 0) {
		/* because of ensure absolute we know it starts with a slash.
		*  since eat_trailing_slashes did not eat the whole path,
		*  what remains must be of the form "/XXX(/XXX)*" (regex).
		*  there might be redundant slashes. */
		if (!!(r = gs_nix_path_ensure_starts_with_lump(InputPathBuf, LenInputPath)))
			goto clean;
		/* eat an XXX part */
		if (!!(r = gs_nix_path_eat_trailing_nonslashes(InputPathBuf, LenInputPath, &LenInputPath)))
			goto clean;
		/* eat an / part */
		if (!!(r = gs_nix_path_eat_trailing_slashes(InputPathBuf, LenInputPath, &LenInputPath)))
			goto clean;
		/* two possibilities: we were on the last /XXX part or not.
		*  path is now empty or of the form /XXX */
	}

	if (LenInputPath == 0) {
		/* handle the 'path is now empty' possibility: output just /, as per dirname(3) */
		ToOutputPtr = OnlySlash;
		ToOutputLen = (sizeof OnlySlash) - 1;
	} else {
		/* handle the 'path is now of the form /XXX' possibility: output verbatim */
		ToOutputPtr = InputPathBuf;
		ToOutputLen = LenInputPath;
	}

	if (OutputPathBufSize < ToOutputLen + 1)
		{ r = 1; goto clean; }

	memmove(ioOutputPathBuf, ToOutputPtr, ToOutputLen);
	memset(ioOutputPathBuf + ToOutputLen, '\0', 1);

	if (oLenOutputPath)
		*oLenOutputPath = ToOutputLen;

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
	int errGlobMagic = GLOB_NOMATCH;

	char PatternBuf[1024] = {};
	size_t LenPattern = 0;

	glob_t Glob = {};

	std::string Accum;

	// FIXME: better break out before running untested code
	GS_LOG(I, S, "hit untested/rarely used function, exiting - file issue report please");
	GS_ASSERT(0);

	if (!!(r = gs_path_append_abs_rel(
		PathBuf, LenPath,
		ExtBuf, LenExt,
		PatternBuf, sizeof PatternBuf, &LenPattern)))
	{
		GS_GOTO_CLEAN();
	}

	if (!!(r = gs_buf_ensure_haszero(PatternBuf, LenPattern + 1)))
		GS_GOTO_CLEAN();

	errGlobMagic = glob(PatternBuf, GLOB_ERR | GLOB_NOESCAPE, NULL, &Glob);
	/* separate GLOB_NOMATCH path for compatibility
           with the windows version of this function */
	if (!!errGlobMagic && errGlobMagic == GLOB_NOMATCH) {
	  Accum.append("");
	  GS_ERR_NO_CLEAN(0);
	}
	if (!!errGlobMagic)
	  GS_ERR_NO_CLEAN(1);

	for (size_t i = 0; i < Glob.gl_pathc; i++) {
	  Accum.append(Glob.gl_pathv[i]);
	  Accum.append(SeparatorBuf, LenSeparator);
	}

	if (Accum.size() + 1 >= ExpandedSize)
		GS_ERR_CLEAN(1);

	memmove(ExpandedBuf, Accum.data(), Accum.size());
	memset(ExpandedBuf + Accum.size(), '\0', 1);

noclean:
	if (oLenExpanded)
		*oLenExpanded = Accum.size();

clean:
	if (!errGlobMagic)
	  globfree(&Glob);

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
		goto clean;
	}

	/* ensure relative and append */

	if (!!(r = gs_path_append_abs_rel(
		PathCurrentExecutableDirBuf, LenPathCurrentExecutableDir,
		RelativeBuf, LenRelative,
		PathModificationBuf, sizeof PathModificationBuf, &LenPathModification)))
	{
		goto clean;
	}

	/* SKIP canonicalize into output AND JUST COPY */
	/* no seriously it sucks that ex realpath(3) is not an
	*  async-signal-safe function. */

	if (!!(r = gs_buf_copy_zero_terminate(
		PathModificationBuf, LenPathModification,
		ioCombinedBuf, CombinedBufSize, oLenCombined)))
	{
		goto clean;
	}

clean:

	return r;
}

int gs_get_current_executable_filename(char *ioFileNameBuf, size_t FileNameSize, size_t *oLenFileName) {
	/* http://man7.org/linux/man-pages/man5/proc.5.html
	*    /proc/[pid]/exe:
	*    If the pathname has been
	*         unlinked, the symbolic link will contain the string
	*         '(deleted)' appended to the original pathname. */
	// FIXME: does move count as unlinking? (probably so)
	//   so if the process has moved itself (during selfupdate)
	//   this call will basically fail (or at least return a weirder name

	int r = 0;

	const char MAGIC_PROC_PATH_NAME[] = "/proc/self/exe";

	if (!!(r = gs_nix_readlink_wrapper(
		MAGIC_PROC_PATH_NAME, (sizeof MAGIC_PROC_PATH_NAME) - 1,
		ioFileNameBuf, FileNameSize, oLenFileName)))
	{
		r = 1; goto clean;
	}

	if (!!(r = gs_nix_path_ensure_absolute(ioFileNameBuf, *oLenFileName)))
		goto clean;

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
		goto clean;
	}

	if (!!(r = gs_nix_absolute_path_directory(
		CurrentExecutableBuf, LenCurrentExecutable,
		ioCurrentExecutableDirBuf, CurrentExecutableDirSize, oLenCurrentExecutableDir)))
	{
		goto clean;
	}

clean:

	return r;
}

int gs_file_exist(
	const char *FileNameBuf, size_t LenFileName,
	size_t *oIsExist)
{
	/* errors count as non-existence */
	int errAccess = gs_nix_access_wrapper(FileNameBuf, LenFileName, F_OK);

	if (oIsExist)
		*oIsExist = !errAccess;

	return 0;
}

int gs_file_exist_ensure(const char *FileNameBuf, size_t LenFileName)
{
	int r = 0;

	size_t IsExist = 0;

	if (!!(r = gs_file_exist(FileNameBuf, LenFileName, &IsExist)))
		goto clean;

	if (!IsExist)
		{ r = 1; goto clean; }

clean:

	return r;
}

int gs_file_is_directory(const char *FileNameBuf, size_t LenFileName,
	size_t *oIsDirectory)
{
  int r = 0;

  struct stat Stat = {};

  // FIXME: ENOENT may not be an error?
  if (!!stat (FileNameBuf, &Stat))
    GS_ERR_CLEAN(1);

  if (oIsDirectory)
    *oIsDirectory = S_ISDIR(Stat.st_mode);
  
 clean:

  return r;
}

int gs_path_is_absolute(const char *PathBuf, size_t LenPath, size_t *oIsAbsolute)
{
	int r = 0;

	size_t IsAbsolute = 0;

	if (LenPath < 1)
		{ r = 1; goto clean; }

	IsAbsolute = PathBuf[0] == '/';

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

	size_t OutputPathEndOffset = 0;

	size_t AbsoluteIsAbsolute = 0;
	size_t RelativeIsAbsolute = 0;

	if (!!(r = gs_path_is_absolute(AbsoluteBuf, LenAbsolute, &AbsoluteIsAbsolute)))
		goto clean;

	if (!!(r = gs_path_is_absolute(RelativeBuf, LenRelative, &RelativeIsAbsolute)))
		goto clean;

	if ((! AbsoluteIsAbsolute) || (RelativeIsAbsolute))
	{ r = 1; goto clean; }

	/* prep output buffer with absolute path */

	if (!!(r = gs_buf_copy_zero_terminate(
		AbsoluteBuf, LenAbsolute,
		ioOutputPathBuf, OutputPathBufSize, &OutputPathEndOffset)))
	{
		goto clean;
	}

	/* append */

	if (!!(r = gs_nix_path_append_midslashing_inplace(
		RelativeBuf, LenRelative,
		ioOutputPathBuf, OutputPathBufSize, OutputPathEndOffset, &OutputPathEndOffset)))
	{
		goto clean;
	}

	if (!!(r = gs_buf_strnlen(ioOutputPathBuf, OutputPathBufSize, oLenOutputPath)))
		goto clean;

clean:

	return r;
}

int gs_file_read_tobuffer_block(
	const char *FileNameBuf, size_t LenFileName,
	char *ioDataBuf, size_t DataSize, size_t *oLenData)
{
	int r = 0;

	int Fd = -1;
	ssize_t cnt = -1;
	size_t Offset = 0;

	if (!!(r = gs_buf_ensure_haszero(FileNameBuf, LenFileName + 1)))
		GS_GOTO_CLEAN();

	while (-1 == (Fd = open(FileNameBuf, O_RDONLY))) {
		if (errno == EINTR)
			continue;
		else if (errno == ENOENT)
			GS_ERR_NO_CLEAN(GS_ERRCODE_NOTFOUND);
		else
			GS_ERR_CLEAN(1);
	}

	while (Offset <= DataSize) {
		while (-1 == (cnt = read(Fd, ioDataBuf + Offset, DataSize - Offset))) {
			if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
				continue;
			else
				GS_ERR_CLEAN(1);
		}
		Offset += cnt;
		if (cnt == 0)
			break;
	}

	if (cnt != 0)
		GS_ERR_CLEAN(1);

noclean:
	if (oLenData)
		*oLenData = Offset;

clean:
	if (Fd != -1)
		close(Fd);

	return r;
}

int gs_file_write_frombuffer(
	const char *FileNameBuf, size_t LenFileName,
	uint8_t *BufferUpdateData, uint32_t BufferUpdateSize)
{
	int r = 0;

	int Fd = -1;

	if (!!(r = gs_buf_ensure_haszero(FileNameBuf, LenFileName + 1)))
		GS_GOTO_CLEAN();

	// FIXME: choice of mask (rwx)
	if (!!(r = gs_nix_open_mask_rwx(FileNameBuf, LenFileName, &Fd)))
	  GS_GOTO_CLEAN();

	if (!!(r = gs_nix_write_wrapper(Fd, (const char *) BufferUpdateData, BufferUpdateSize)))
	  GS_GOTO_CLEAN();

clean:
	gs_nix_close_wrapper_noerr(Fd);
	
	return r;
}

int gs_rename_wrapper(
	const char *SrcFileNameBuf, size_t LenSrcFileName,
	const char *DstFileNameBuf, size_t LenDstFileName)
{
  return gs_nix_rename_wrapper(
    SrcFileNameBuf, LenSrcFileName,
    DstFileNameBuf, LenDstFileName);
}

int gs_directory_create_unless_exist(
	const char *DirNameBuf, size_t LenDirName)
{
        /* non-reentrant (ex use of errno) */
  
	int r = 0;

	/* 0777 aka default for linux - remember umask applies */
	mode_t Mode = S_IRUSR | S_IWUSR | S_IXUSR |
	  S_IRGRP | S_IWGRP | S_IXGRP |
	  S_IROTH | S_IWOTH | S_IXOTH;
	
	if (!!(r = gs_buf_ensure_haszero(DirNameBuf, LenDirName + 1)))
		GS_GOTO_CLEAN();

	if (!!mkdir(DirNameBuf, Mode)) {
	    if (errno == EEXIST)
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
  int r = 0;
  
  std::vector<const char *> Argv;

  pid_t PidChild = -1;
  
  if (!!(r = gs_buf_ensure_haszero(FileNameParentBuf, LenFileNameParent + 1)))
    GS_GOTO_CLEAN();

  if (!!(r = gs_buf_ensure_haszero(CmdLineBuf, LenCmdLine + 1)))
    GS_GOTO_CLEAN();
  
  Argv.push_back(&FileNameParentBuf[0]);
  
  for (size_t Offset = 0; Offset < LenCmdLine; Offset++) {
    Argv.push_back(&CmdLineBuf[Offset]);
    while (Offset < LenCmdLine && CmdLineBuf[Offset] != '\0')
      Offset++;
  }

  /* argv must be terminated by NULL, see execv(2) */
  Argv.push_back(NULL);

  if ((PidChild = fork()) == -1)
    GS_ERR_CLEAN(1);
  if (PidChild == 0) {
    /* consider calling _Exit (C99) on failure */
    if (!!(r = execv(FileNameParentBuf, (char * const *) Argv.data())))
      exit(EXIT_FAILURE);
  }
  else {
    int StatusChild = 0;
    pid_t PidWait = -1;
    if ((PidWait = waitpid(PidChild, &StatusChild, 0)) == -1)
      GS_ERR_CLEAN(1);
    if (! WIFEXITED(StatusChild))
      GS_ERR_CLEAN(1);
    if (WEXITSTATUS(StatusChild) != EXIT_SUCCESS)
      GS_ERR_CLEAN(1);
  }

 clean:

  return r;
}

int gs_posixstyle_open_read(const char *FileName)
{
	int r = -1;

	while (-1 == (r = open(FileName, O_RDONLY | O_CLOEXEC)) && errno == EINTR)
		{}

	return r;
}

int gs_posixstyle_fstat(int Fd, struct gs_stat *ioStat)
{
	int r = -1;

	struct stat Stat = {};

	while (-1 == (r = fstat(Fd, &Stat)) && errno == EINTR)
		{}

	if (-1 == r)
		goto clean;

	ioStat->mStMode_IfReg = (Stat.st_mode & S_IFMT) == S_IFREG;
	ioStat->mStSize = Stat.st_size;

clean:

	return r;
}

int gs_posixstyle_close(int Fd)
{
	int r = -1;

	while (-1 == (r = close(Fd)) && errno == EINTR)
		{}

	return r;
}

int gs_nix_write_wrapper(int fd, const char *Buf, size_t LenBuf) {
	/* non-reentrant (ex use of errno)
	*  http://stackoverflow.com/questions/1694164/is-errno-thread-safe/1694170#1694170
	*    even if thread local errno makes the function (sans side-effects) thread-safe
	*    receiving signal within signal on same thread would require it to also be reentrant
	*  http://man7.org/linux/man-pages/man7/signal-safety.7.html
	*    async-signal-safe functions: write and fsync are listed */

	int r = 0;

	size_t count_total = 0;

	if (fd == -1)
		{ r = 1; goto clean; }

	while (count_total < LenBuf) {
		ssize_t count = 0;

		count = write(fd, Buf + count_total, LenBuf - count_total);

		if (count == -1 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR))
			continue;
		else if (count == -1)
			{ r = 1; goto clean; }

		/* count >= 0 */

		count_total += count;

	}

	/* http://stackoverflow.com/questions/26257171/flush-kernel-buffers-for-stdout/26258312#26258312
	*    probably do not need to fsync the console
	*    but we may or may not be writing to the console */

	while (!!fsync(fd)) {
		/* EROFS / EINVAL expected for a console directed write - just continue */
		if (errno == EROFS || errno == EINVAL)
			break;
		else
			{ r = 1; goto clean; }
	}

clean:

	return r;
}

int gs_nix_write_stdout_wrapper(const char *Buf, size_t LenBuf) {
	return gs_nix_write_wrapper(STDOUT_FILENO, Buf, LenBuf);
}

int gs_nix_unlink_wrapper(const char *FileNameBuf, size_t LenFileName)
{
	/* http://man7.org/linux/man-pages/man7/signal-safety.7.html
	*    async-signal-safe functions: unlink is listed */

	int r = 0;

	if (!!(r = gs_buf_ensure_haszero(FileNameBuf, LenFileName + 1)))
		goto clean;

	if (!!unlink(FileNameBuf))
		{ r = 1; goto clean; }

clean:

	return r;
}

int gs_nix_rename_wrapper(
	const char *SrcFileNameBuf, size_t LenSrcFileName,
	const char *DstFileNameBuf, size_t LenDstFileName)
{
	/* http://man7.org/linux/man-pages/man7/signal-safety.7.html
	*    async-signal-safe functions: rename is listed */

	int r = 0;

	if (!!(r = gs_buf_ensure_haszero(SrcFileNameBuf, LenSrcFileName + 1)))
		goto clean;

	if (!!(r = gs_buf_ensure_haszero(DstFileNameBuf, LenDstFileName + 1)))
		goto clean;

	if (!!rename(SrcFileNameBuf, DstFileNameBuf))
		{ r = 1; goto clean; }

clean:

	return r;
}

int gs_nix_open_tmp_mask_rwx(int *oFdTmpFile) {
	/* http://man7.org/linux/man-pages/man7/signal-safety.7.html
	*    async-signal-safe functions: open is listed */

	int r = 0;

	// FIXME: O_TMPFILE is super magic

	// FIXME: O_TMPFILE introduced as late as Linux 3.11 kernel release
	//   https://kernelnewbies.org/Linux_3.11#head-8be09d59438b31c2a724547838f234cb33c40357
	// FIXME: even worse, O_TMPFILE requires support by the filesystem (as per open(2))

	// FIXME: besides all these O_TMPFILE problems, the way to link it into filesystem is magic
	//   therefore just do not use this function please.

	const char MagicOTmpFileName[] = ".";
	size_t LenMagicOTmpFileName = (sizeof MagicOTmpFileName) - 1;

	/* user read write and execute, add other access flags? */
	if (!!(r = gs_nix_open_wrapper(
		MagicOTmpFileName, LenMagicOTmpFileName,
		O_WRONLY | O_TMPFILE | O_CLOEXEC,
		S_IRUSR | S_IWUSR | S_IXUSR,
		oFdTmpFile)))
	{
		goto clean;
	}

clean:

	return r;
}

int gs_nix_open_mask_rw(
	const char *LogFileNameBuf, size_t LenLogFileName,
	int *oFdLogFile)
{
	/* http://man7.org/linux/man-pages/man7/signal-safety.7.html
	*    async-signal-safe functions: open is listed */

	int r = 0;

	/* user read and write, add other access flags? */
	if (!!(r = gs_nix_open_wrapper(
		LogFileNameBuf, LenLogFileName,
		O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC,
		S_IRUSR | S_IWUSR,
		oFdLogFile)))
	{
		goto clean;
	}

clean:

	return r;
}

int gs_nix_open_mask_rwx(
	const char *LogFileNameBuf, size_t LenLogFileName,
	int *oFdLogFile)
{
	/* http://man7.org/linux/man-pages/man7/signal.7.html
	*    async-signal-safe functions: open is listed */

	int r = 0;

	/* user read write and execute, add other access flags? */
	if (!!(r = gs_nix_open_wrapper(
		LogFileNameBuf, LenLogFileName,
		O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC,
		S_IRUSR | S_IWUSR | S_IXUSR,
		oFdLogFile)))
	{
		goto clean;
	}

clean:

	return r;
}

int gs_nix_fork_exec(
	char *ParentArgvUnifiedBuf, size_t LenParentArgvUnified,
	char **ArgvPtrs, size_t *LenArgvPtrs)
{
	/* http://man7.org/linux/man-pages/man7/signal-safety.7.html
	*    async-signal-safe functions: fork is listed.
	*    execvp is actually not but happens in child.
	*    fork actually mentioned to be candidate for de-listing */

	int r = 0;

	pid_t Pid = 0;
	int errExec = -1;

	/* fork can result in EAGAIN, but does not seem resumable */
	if (-1 == (Pid = fork()))
		{ r = 1; goto clean; }

	if (Pid == 0) {
		/* child */
		if (-1 == (errExec = execvp(ArgvPtrs[0], ArgvPtrs)))
			{ r = 1; goto clean; }
	} 
	else {
		/* parent */
		/* nothing - just return */
	}

clean:

	return r;
}
