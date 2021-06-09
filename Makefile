.PATH: ${.CURDIR}/src

KMOD=	ddfs
SRCS=	kvs.h ddfs.h dir.h ddfs_vfsops.c ddfs_node.c kvs.c ddfs_vnops.c ddfs_lookup.c 
SRCS+=  vnode_if.h opt_global.h

.include <bsd.kmod.mk>
