enum {
	/* root level files */
	Qroot = 1,
	Qctl,
	Qpush,
	Qpull,
	Qmax,	/* keep file access honest */
	
	Bufsize = 4192,

};

/* mongo.c */
static void	usage(char *name);
static void	fsinit(void);
static int	ctl_read(Spfilefid *fid, u64 offset, u32 count, u8 *data, Spreq *req);
static int	ctl_write(Spfilefid *fid, u64 offset, u32 count, u8 *data, Spreq *req);
static int	ctl_wstat(Spfile *, Spstat *);
static int	pull_read(Spfilefid *fid, u64 offset, u32 count, u8 *data, Spreq *req);
static int	push_read(Spfilefid *fid, u64 offset, u32 count, u8 *data, Spreq *req);
static Spfile *dir_next(Spfile *dir, Spfile *prevchild);
static Spfile *dir_first(Spfile *dir);


