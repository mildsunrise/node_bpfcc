/** Count task switches with from and to PIDs */

import { loadSync } from '..'
import { readFileSync } from 'fs'

const code = readFileSync(`${__dirname}/task_switch.c`, 'utf8')
const bpf = loadSync(code)
bpf.attachKprobe('finish_task_switch', 'count_sched')
const statsMap = bpf.getRawMap('stats')

console.log('Tracing...')
setTimeout(() => {
    const entries = [...statsMap]
        .map(([k, v]) => [k, v.readBigUInt64LE(0)] as [Buffer, bigint])
        .sort((a, b) => Number(a[1] - b[1]))
    for (const [k, v] of entries) {
        const prevPid = k.readUInt32LE(0), currPid = k.readUInt32LE(4)
        console.log(`task_switch[${prevPid}->${currPid}]=${v}`)
    }
}, 3000)
