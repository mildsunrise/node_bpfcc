/** Count task switches with from and to PIDs */

import { loadSync } from '..'
import { readFileSync } from 'fs'
import { TypeConversion } from 'bpf'
import { asUint32Array, asBigUint64Array } from 'bpf/dist/util'

const code = readFileSync(`${__dirname}/task_switch.c`, 'utf8')
const bpf = loadSync(code)
bpf.attachKprobe('finish_task_switch', 'count_sched')

const keyConv: TypeConversion<{ prevPid: number, currPid: number }> = {
    parse: (buf) => {
        const [ prevPid, currPid ] = asUint32Array(buf)
        return { prevPid, currPid }
    },
    format: (buf, x) => {
        asUint32Array(buf).set([ x.prevPid, x.currPid ])
    }
}
const valueConv: TypeConversion<bigint> = {
    parse: (buf) => asBigUint64Array(buf)[0],
    format: (buf, x) => asBigUint64Array(buf)[0] = x,
}
const statsMap = bpf.getMap('stats', keyConv, valueConv)

console.log('Tracing...')
setTimeout(() => {
    const entries = [...statsMap]
    entries.sort((a, b) => Number(a[1] - b[1]))
    for (const [k, v] of entries)
        console.log(`task_switch[${k.prevPid}->${k.currPid}]=${v}`)
}, 3000)
